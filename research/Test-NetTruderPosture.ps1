#requires -Version 5.1
<#
    NetTruder // LOLBAS Research Lab
    ------------------------------------------------------------------
    Read-only posture inventory for publicly documented living-off-the-
    land execution primitives (LOLBAS), worm-like lateral behaviour and
    Linux/Unix GTFOBins. It also runs an optional set of inert marker
    probes used to validate telemetry coverage.

    Three catalogs are loaded:
      techniques.json  Windows proxy execution and script hosts
      worm.json        Windows worm-like lateral behaviour
      gtfobins.json    Linux / Unix GTFOBins, presence-checked only

    This script does not change security settings. It writes one JSON
    report, one Markdown report and a marker log under
    %LOCALAPPDATA%\NetTruder\lab by default.

    Marker probes only append a line to markers.log. They do not use
    the network, do not persist, do not hide windows and do not carry
    a payload. Both -RunMarkerProbes and -Yes are required.

    Linux entries are checked through a readable \\wsl$\ filesystem
    only. No Linux binary is executed. An unreadable WSL distribution
    is reported as not evaluated, never as a clean result.
#>
[CmdletBinding()]
param(
    [switch]$RunMarkerProbes,
    [switch]$Yes,
    [string]$OutDir = (Join-Path $env:LOCALAPPDATA 'NetTruder\lab')
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=== ' + $Text + ' ' + ('=' * [Math]::Max(0, 58 - $Text.Length))) -ForegroundColor Cyan
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# Membership and elevation are different facts. A UAC-filtered administrator
# token still contains the Administrators SID (deny-only) but IsInRole returns
# false and the Security log cannot be read. These helpers report both facts
# plus the SeSecurityPrivilege state, so the proof can name the real cause
# instead of printing a blanket "needs elevation".
function Test-AdminGroup {
    param([string]$Sid = 'S-1-5-32-544')
    try {
        if ('NetTruderToken' -as [type]) {
            if ([NetTruderToken]::HasGroup($Sid)) { return $true }
        }
    } catch { }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        foreach ($g in $id.Groups) {
            if ([string]$g.Value -eq $Sid) { return $true }
        }
        # A UAC-filtered token marks Administrators deny-only. The SID is not
        # in .Groups but it is exposed as a denyonlysid claim.
        foreach ($c in $id.Claims) {
            if (([string]$c.Type).ToLower().IndexOf('denyonlysid') -ge 0 -and [string]$c.Value -eq $Sid) { return $true }
        }
    } catch { }
    return $false
}

function Get-TokenDiagnostics {
    $state = [pscustomobject]@{
        adminGroup       = $false
        tokenElevated    = $false
        elevationType    = 'unknown'
        integrity        = 'unknown'
        privilegePresent = $false
        privilegeEnabled = $false
        probeError       = ''
    }

    try {
        if (-not ('NetTruderToken' -as [type])) {
            $src = @'
using System;
using System.Runtime.InteropServices;
public class NetTruderToken {
    [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int need);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool LookupPrivilegeValue(string host, string name, out LUID luid);
    [DllImport("advapi32.dll")] public static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] public static extern IntPtr GetSidSubAuthority(IntPtr sid, int index);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool ConvertStringSidToSid(string str, out IntPtr sid);
    [DllImport("advapi32.dll")] public static extern bool EqualSid(IntPtr a, IntPtr b);
    [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr h);
    const uint TOKEN_QUERY = 0x0008;

    static IntPtr Open() {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out tok)) return IntPtr.Zero;
        return tok;
    }
    static int ReadInt(int cls) {
        IntPtr tok = Open();
        if (tok == IntPtr.Zero) return -1;
        try {
            int need;
            IntPtr buf = Marshal.AllocHGlobal(8);
            try {
                if (!GetTokenInformation(tok, cls, buf, 8, out need)) return -1;
                return Marshal.ReadInt32(buf);
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(tok); }
    }
    public static bool IsElevated() { return ReadInt(20) == 1; }
    public static int ElevationType() { return ReadInt(18); }
    public static int IntegrityRid() {
        IntPtr tok = Open();
        if (tok == IntPtr.Zero) return -1;
        try {
            int need = 0;
            GetTokenInformation(tok, 25, IntPtr.Zero, 0, out need);
            if (need <= 0) return -1;
            IntPtr buf = Marshal.AllocHGlobal(need);
            try {
                if (!GetTokenInformation(tok, 25, buf, need, out need)) return -1;
                IntPtr sid = Marshal.ReadIntPtr(buf);
                byte n = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                if (n == 0) return -1;
                return Marshal.ReadInt32(GetSidSubAuthority(sid, (int)n - 1));
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(tok); }
    }
    public static int PrivState(string name) {
        IntPtr tok = Open();
        if (tok == IntPtr.Zero) return -1;
        try {
            LUID want;
            if (!LookupPrivilegeValue(null, name, out want)) return -1;
            int need = 0;
            GetTokenInformation(tok, 3, IntPtr.Zero, 0, out need);
            if (need <= 0) return -1;
            IntPtr buf = Marshal.AllocHGlobal(need);
            try {
                if (!GetTokenInformation(tok, 3, buf, need, out need)) return -1;
                int count = Marshal.ReadInt32(buf);
                int size = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                long baseAddr = buf.ToInt64() + 4;
                for (int i = 0; i < count; i++) {
                    LUID_AND_ATTRIBUTES la = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(new IntPtr(baseAddr + (i * size)), typeof(LUID_AND_ATTRIBUTES));
                    if (la.Luid.Low == want.Low && la.Luid.High == want.High) {
                        return ((la.Attributes & 0x00000002) != 0) ? 2 : 1;
                    }
                }
                return 0;
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(tok); }
    }
    public static bool HasGroup(string sidString) {
        IntPtr want;
        if (!ConvertStringSidToSid(sidString, out want)) return false;
        IntPtr tok = Open();
        if (tok == IntPtr.Zero) { LocalFree(want); return false; }
        try {
            int need = 0;
            GetTokenInformation(tok, 2, IntPtr.Zero, 0, out need);
            if (need <= 0) return false;
            IntPtr buf = Marshal.AllocHGlobal(need);
            try {
                if (!GetTokenInformation(tok, 2, buf, need, out need)) return false;
                int count = Marshal.ReadInt32(buf);
                int size = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                long baseAddr = buf.ToInt64() + (IntPtr.Size == 8 ? 8 : 4);
                for (int i = 0; i < count; i++) {
                    SID_AND_ATTRIBUTES sa = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(new IntPtr(baseAddr + (i * size)), typeof(SID_AND_ATTRIBUTES));
                    if (EqualSid(sa.Sid, want)) return true;
                }
                return false;
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(tok); LocalFree(want); }
    }
}
'@
            Add-Type -TypeDefinition $src -ErrorAction Stop
        }

        $state.adminGroup = (Test-AdminGroup)
        $state.tokenElevated = [NetTruderToken]::IsElevated()

        switch ([NetTruderToken]::ElevationType()) {
            1 { $state.elevationType = 'default' }
            2 { $state.elevationType = 'full' }
            3 { $state.elevationType = 'limited' }
        }

        $rid = [NetTruderToken]::IntegrityRid()
        if ($rid -ge 0x5000) { $state.integrity = 'protected' }
        elseif ($rid -ge 0x4000) { $state.integrity = 'system' }
        elseif ($rid -ge 0x3000) { $state.integrity = 'high' }
        elseif ($rid -ge 0x2000) { $state.integrity = 'medium' }
        elseif ($rid -ge 0x1000) { $state.integrity = 'low' }
        elseif ($rid -ge 0) { $state.integrity = 'untrusted' }

        $priv = [NetTruderToken]::PrivState('SeSecurityPrivilege')
        if ($priv -eq 1 -or $priv -eq 2) { $state.privilegePresent = $true }
        if ($priv -eq 2) { $state.privilegeEnabled = $true }
    } catch {
        $state.probeError = $_.Exception.Message
        # Fall back to the managed check so the report still has a token answer.
        $state.tokenElevated = (Test-Admin)
    }

    return $state
}

function Get-ElevationHint {
    param($E)
    if ($E.securityReadable) {
        return 'The Security log is readable in this session; 4688 coverage can be measured directly.'
    }
    if (-not $E.adminGroup -and -not $E.tokenElevated) {
        return 'This account is not in Administrators and the token is not elevated. Reading the Security log needs an administrator token with SeSecurityPrivilege. Run Launch-Elevated.cmd from an administrator account. NetTruder never disables UAC.'
    }
    if ($E.adminGroup -and -not $E.tokenElevated) {
        return 'This account is in Administrators, but UAC gave this process a filtered token. Group membership is not the same as an elevated token. The Security log needs the elevated token, so right-click Launch-Elevated.cmd, choose Run as administrator and accept the UAC prompt. NetTruder never disables UAC or auto-elevates.'
    }
    if ($E.tokenElevated -and -not $E.privilegePresent) {
        return 'The token is elevated, but SeSecurityPrivilege is not present in it. A local or domain policy (Manage auditing and security log) may have removed the privilege from this account. Review secpol.msc and the account rights assignment; NetTruder reports the state and does not grant rights silently.'
    }
    if ($E.tokenElevated -and $E.privilegePresent -and -not $E.privilegeEnabled) {
        return 'The token is elevated and SeSecurityPrivilege is present but disabled. NetTruder tried to enable it in-process; the attempt result is shown above. If the read still fails, the channel access (SDDL) may deny this account.'
    }
    return 'The token is elevated and SeSecurityPrivilege is present, yet the Security log read failed. The channel SDDL or a group policy may deny read access. Inspect it with wevtutil gl Security and compare the channel access with the account SID.'
}

function Get-LogState {
    param([string]$Name)
    try {
        $log = Get-WinEvent -ListLog $Name -ErrorAction Stop
        return [pscustomobject]@{
            name = $Name
            enabled = [bool]$log.IsEnabled
            records = [int64]$log.RecordCount
        }
    } catch {
        return $null
    }
}

function Get-SignatureInfo {
    param([string]$Path)
    $out = [pscustomobject]@{
        status = ''
        signer = ''
        version = ''
    }
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $out.version = [string]$item.VersionInfo.FileVersion
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $out.status = [string]$sig.Status
        if ($sig.SignerCertificate) {
            $subject = [string]$sig.SignerCertificate.Subject
            $m = [regex]::Match($subject, 'CN=([^,]+)')
            if ($m.Success) { $out.signer = $m.Groups[1].Value } else { $out.signer = $subject }
        }
    } catch {
        $out.status = 'error'
    }
    return $out
}

# Enable SeSecurityPrivilege in the current process. Reading the Security log
# needs this privilege even when the account is an administrator, because the
# token can hold a privilege that is disabled by default. This is a standard
# token adjustment, not an attempt to bypass a control. The result is a
# string so "not assigned to this token" is not mistaken for success.
function Enable-SecurityPrivilege {
    param([string]$Name = 'SeSecurityPrivilege')
    try {
        if (-not ('NetTruderPriv' -as [type])) {
            $src = @'
using System;
using System.Runtime.InteropServices;
public class NetTruderPriv {
    [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attr; }
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool LookupPrivilegeValue(string host, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TOKEN_PRIVILEGES np, uint len, IntPtr prev, IntPtr rl);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    public static string Enable(string name) {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out tok)) return "open-token-failed:" + Marshal.GetLastWin32Error();
        LUID luid;
        if (!LookupPrivilegeValue(null, name, out luid)) { int e1 = Marshal.GetLastWin32Error(); CloseHandle(tok); return "lookup-failed:" + e1; }
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.Count = 1; tp.Luid = luid; tp.Attr = 0x00000002;
        bool ok = AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        CloseHandle(tok);
        if (!ok) return "failed:" + err;
        if (err == 1300) return "not-assigned:1300";
        return "enabled:" + err;
    }
}
'@
            Add-Type -TypeDefinition $src -ErrorAction Stop
        }
        return [NetTruderPriv]::Enable($Name)
    } catch {
        return ('failed:' + $_.Exception.Message)
    }
}

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Title,
        [string]$Detail,
        [string]$Control = '',
        [string[]]$Fix = @(),
        [string]$Enable = '',
        [string]$Native = ''
    )
    $script:findings += [pscustomobject]@{
        severity = $Severity
        title = $Title
        detail = $Detail
        control = $Control
        fix = @($Fix)
        enable = $Enable
        native = $Native
    }
}

function New-ControlRow {
    param(
        [string]$Id,
        [string]$Name,
        $Value,
        [string]$Source,
        [string]$Detail,
        [string[]]$Fix = @(),
        [string]$Enable = '',
        [string]$Native = '',
        [string]$Severity = 'info',
        [switch]$BadWhenOn,
        [switch]$Neutral
    )
    return [pscustomobject]@{
        id = $Id
        name = $Name
        value = [bool]$Value
        source = $Source
        detail = $Detail
        fix = @($Fix)
        enable = $Enable
        native = $Native
        severity = $Severity
        badWhenOn = [bool]$BadWhenOn
        neutral = [bool]$Neutral
    }
}

function Test-LogReadable {
    param([string]$Name)
    try {
        $null = Get-WinEvent -LogName $Name -MaxEvents 1 -ErrorAction Stop
        return [pscustomobject]@{ accessible = $true; error = '' }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'No events were found') { return [pscustomobject]@{ accessible = $true; error = '' } }
        return [pscustomobject]@{ accessible = $false; error = $msg }
    }
}

function Get-RecentEventCount {
    param([string]$LogName, [int]$Id, [int]$Minutes)
    try {
        $since = (Get-Date).AddMinutes(-1 * $Minutes)
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Id; StartTime = $since } -MaxEvents 500 -ErrorAction Stop)
        return [pscustomobject]@{ accessible = $true; count = $ev.Count; error = '' }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'No events were found') {
            return [pscustomobject]@{ accessible = $true; count = 0; error = '' }
        }
        return [pscustomobject]@{ accessible = $false; count = 0; error = $msg }
    }
}

# Targeted proof: count only 4688 events whose new-process image is one of the
# probe hosts. A broad before/after count can be inflated by unrelated activity
# (including this tool's own PowerShell use), so it is kept only as context.
function Get-ProbeProcessHits {
    param([datetime]$Since, [string[]]$Hosts)
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $Since } -MaxEvents 500 -ErrorAction Stop)
        $names = @{}
        foreach ($h in $Hosts) {
            if ($h) { $names[[IO.Path]::GetFileName($h).ToLowerInvariant()] = $true }
        }
        $hits = 0
        foreach ($e in $ev) {
            try {
                $np = [string]$e.Properties[5].Value
                $leaf = [IO.Path]::GetFileName($np).ToLowerInvariant()
                if ($names.ContainsKey($leaf)) { $hits++ }
            } catch { }
        }
        return [pscustomobject]@{ accessible = $true; hits = $hits; error = '' }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'No events were found') { return [pscustomobject]@{ accessible = $true; hits = 0; error = '' } }
        return [pscustomobject]@{ accessible = $false; hits = 0; error = $msg }
    }
}

# Fallback proof when the Security log is not readable. Sysmon event 1 carries
# the image path in named XML fields, so parse the XML instead of relying on a
# positional property index.
function Get-SysmonProcessHits {
    param([datetime]$Since, [string[]]$Hosts)
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $Since } -MaxEvents 500 -ErrorAction Stop)
        $names = @{}
        foreach ($h in $Hosts) {
            if ($h) { $names[[IO.Path]::GetFileName($h).ToLowerInvariant()] = $true }
        }
        $hits = 0
        foreach ($e in $ev) {
            try {
                $xml = [xml]$e.ToXml()
                $img = ''
                foreach ($d in @($xml.Event.EventData.Data)) {
                    if ([string]$d.Name -eq 'Image') { $img = [string]$d.'#text'; break }
                }
                if (-not $img) { continue }
                $leaf = [IO.Path]::GetFileName($img).ToLowerInvariant()
                if ($names.ContainsKey($leaf)) { $hits++ }
            } catch { }
        }
        return [pscustomobject]@{ accessible = $true; hits = $hits; error = '' }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'No events were found') { return [pscustomobject]@{ accessible = $true; hits = 0; error = '' } }
        return [pscustomobject]@{ accessible = $false; hits = 0; error = $msg }
    }
}

# Targeted proof for content: 4104 records include the script text, so a match
# on the marker token can only come from marker.ps1. This avoids counting
# unrelated 4104 events (AMSI can emit them even when logging is off).
function Get-ContentProbeHits {
    param([datetime]$Since, [string]$Token)
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $Since } -MaxEvents 500 -ErrorAction Stop)
        $hits = 0
        foreach ($e in $ev) {
            if ($e.Message -and $e.Message.Contains($Token)) { $hits++ }
        }
        return [pscustomobject]@{ accessible = $true; hits = $hits; error = '' }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'No events were found') { return [pscustomobject]@{ accessible = $true; hits = 0; error = '' } }
        return [pscustomobject]@{ accessible = $false; hits = 0; error = $msg }
    }
}

# Read-only WSL discovery. Distros come from the per-user Lxss registry key and
# presence is checked through \\wsl$ only. wsl.exe is not started and no Linux
# binary is executed.
function Get-WslState {
    $state = [pscustomobject]@{
        checked = $false
        available = $false
        distros = @()
        readable = @()
        error = ''
    }
    $names = @()
    try {
        foreach ($k in @(Get-ChildItem -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction Stop)) {
            try {
                $n = [string](Get-ItemProperty -LiteralPath $k.PSPath -Name DistributionName -ErrorAction Stop).DistributionName
                if ($n) { $names += $n }
            } catch { }
        }
    } catch {
        $state.error = 'WSL registry key not readable'
        return $state
    }
    $state.checked = $true
    $state.distros = @($names)
    if ($names.Count -eq 0) {
        $state.error = 'no WSL distributions registered'
        return $state
    }
    $readable = @()
    foreach ($n in $names) {
        $root = '\\wsl$\' + $n
        try {
            if (Test-Path -LiteralPath $root) { $readable += $n }
        } catch { }
    }
    $state.readable = @($readable)
    $state.available = ($readable.Count -gt 0)
    if (-not $state.available) {
        $state.error = 'WSL registered but \\wsl$ is not readable from this session'
    }
    return $state
}

function Resolve-LinuxPresence {
    param($Tech, $Wsl)
    $out = [pscustomobject]@{ present = $null; path = ''; note = '' }
    if ($null -eq $Wsl -or -not $Wsl.available) {
        $why = 'not evaluated'
        if ($Wsl -and $Wsl.error) { $why = $why + ': ' + $Wsl.error }
        $out.note = $why + '. No Linux binary was executed.'
        return $out
    }
    foreach ($d in @($Wsl.readable)) {
        foreach ($dir in @('/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/local/bin', '/snap/bin')) {
            $p = '\\wsl$\' + $d + ($dir -replace '/', '\') + '\' + [string]$Tech.host
            try {
                if (Test-Path -LiteralPath $p) {
                    $out.present = $true
                    $out.path = $p
                    $out.note = 'found in WSL distribution ' + $d + ' (presence only; not executed)'
                    return $out
                }
            } catch { }
        }
    }
    $out.present = $false
    $out.note = 'not found in readable WSL binary paths (presence only; not executed)'
    return $out
}

# ---------------------------------------------------------------------------
# Catalogs
# ---------------------------------------------------------------------------
$catalogFiles = @(
    [pscustomobject]@{ file = 'techniques.json'; label = 'LOLBAS'; platform = 'windows' }
    [pscustomobject]@{ file = 'worm.json'; label = 'Worm-like'; platform = 'windows' }
    [pscustomobject]@{ file = 'gtfobins.json'; label = 'GTFOBins'; platform = 'linux' }
    [pscustomobject]@{ file = 'hevd-catalog.json'; label = 'HEVD Source'; platform = 'windows' }
)

$catalogs = @()
$allTechniques = @()
foreach ($cf in $catalogFiles) {
    $path = Join-Path $PSScriptRoot $cf.file
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host ('Catalog not found: ' + $path) -ForegroundColor Yellow
        continue
    }
    try {
        $doc = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Write-Host ('Could not parse ' + $cf.file + ': ' + $_.Exception.Message) -ForegroundColor Red
        continue
    }
    $count = 0
    foreach ($t in @($doc.techniques)) {
        if ($null -eq $t) { continue }
        if (-not $t.platform) { $t | Add-Member -NotePropertyName platform -NotePropertyValue $cf.platform -Force }
        if (-not $t.group) { $t | Add-Member -NotePropertyName group -NotePropertyValue ([string]$t.family) -Force }
        if (-not $t.method) { $t | Add-Member -NotePropertyName method -NotePropertyValue 'General' -Force }
        $t | Add-Member -NotePropertyName catalog -NotePropertyValue $cf.label -Force
        $allTechniques += $t
        $count++
    }
    $catalogs += [pscustomobject]@{ file = $cf.file; label = $cf.label; version = [string]$doc.version; count = $count }
}

if ($allTechniques.Count -eq 0) {
    Write-Host 'No technique catalog could be loaded.' -ForegroundColor Red
    exit 2
}

$catalogVersionText = (($catalogs | ForEach-Object { $_.label + ' ' + $_.version }) -join ' | ')

# Observed defensive blocks are kept in a separate file because they are
# host-specific evidence, not generic technique knowledge. A block is a positive
# control result; it is never used to upgrade a coverage gap to OK.
$blockCatalog = $null
$allBlocks = @()
$blocksById = @{}
$blocksPath = Join-Path $PSScriptRoot 'blocks.json'
if (Test-Path -LiteralPath $blocksPath) {
    try {
        $blockCatalog = Get-Content -LiteralPath $blocksPath -Raw | ConvertFrom-Json
        foreach ($b in @($blockCatalog.blocks)) {
            if ($null -eq $b) { continue }
            $allBlocks += $b
            $key = [string]$b.tech
            if ($blocksById.ContainsKey($key)) {
                $blocksById[$key] = @($blocksById[$key]) + @($b)
            } else {
                $blocksById[$key] = @($b)
            }
        }
    } catch {
        Write-Host ('Could not parse block register: ' + $_.Exception.Message) -ForegroundColor Yellow
        $blockCatalog = $null
        $allBlocks = @()
        $blocksById = @{}
    }
}

$session = Get-TokenDiagnostics
$isAdmin = $session.tokenElevated
$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
$wslState = Get-WslState

Write-Host ''
Write-Host 'NETTRUDER // LOLBAS RESEARCH LAB' -ForegroundColor Green
Write-Host ('Catalog ' + $catalogVersionText + ' | ' + $stamp.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ('Host ' + $env:COMPUTERNAME + ' | user ' + $env:USERDOMAIN + '\' + $env:USERNAME + ' | elevated token ' + $isAdmin + ' | admin group ' + $session.adminGroup + ' | integrity ' + $session.integrity)
Write-Host 'Read-only inventory. No security setting is changed by this script.'

Write-Section 'CONTROL PLANE'

$controls = [ordered]@{
    cmdline       = $false
    sysmon        = $false
    scriptblock   = $false
    modulelog     = $false
    transcription = $false
    amsi          = $false
    applocker     = $false
    wdac          = $false
    asr           = $false
    wsh           = $true
    wshRemote     = $null
    trustPolicy   = $null
}

$controls.cmdline = ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq 1)
$controls.scriptblock = ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1)
$controls.modulelog = ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging') -eq 1)
$controls.transcription = ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting') -eq 1)

$sysmonServices = @(Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
$controls.sysmon = ($sysmonServices.Count -gt 0)

$amsiProviders = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue)
$controls.amsi = ($amsiProviders.Count -gt 0)

$applockerRules = 0
foreach ($kind in @('Exe', 'Script', 'Msi', 'Dll')) {
    $keyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\' + $kind
    try {
        $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop
        $applockerRules += @($key.GetValueNames()).Count
    } catch { }
}
$controls.applocker = ($applockerRules -gt 0)

$wdacPolicies = @(Get-ChildItem (Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active') -Filter '*.cip' -ErrorAction SilentlyContinue)
$controls.wdac = ($wdacPolicies.Count -gt 0)

$asrTotal = 0
$asrBlock = 0
$asrAudit = 0
try {
    $mp = Get-MpPreference -ErrorAction Stop
    $asrIds = @($mp.AttackSurfaceReductionRules_Ids)
    $asrActions = @($mp.AttackSurfaceReductionRules_Actions)
    $asrTotal = $asrIds.Count
    for ($i = 0; $i -lt $asrIds.Count; $i++) {
        $action = 0
        if ($i -lt $asrActions.Count) { $action = [int]$asrActions[$i] }
        if ($action -eq 1 -or $action -eq 6) { $asrBlock++ }
        elseif ($action -eq 2) { $asrAudit++ }
    }
} catch { }
$controls.asr = ($asrBlock -gt 0)

$wshEnabled = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled'
if ($null -eq $wshEnabled) { $controls.wsh = $true } else { $controls.wsh = ([int]$wshEnabled -ne 0) }
$controls.wshRemote = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Remote'
$controls.trustPolicy = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'TrustPolicy'

$psLog = Get-LogState 'Microsoft-Windows-PowerShell/Operational'
$sysmonLog = $null
if ($controls.sysmon) { $sysmonLog = Get-LogState 'Microsoft-Windows-Sysmon/Operational' }

$nl = "`n"
$enableCmdline = 'auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable' + $nl + 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f'
$enableScriptBlock = 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f'
$enableModuleLog = 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f' + $nl + 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f'
$enableTranscription = 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f' + $nl + 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\ProgramData\NetTruder\transcripts" /f' + $nl + 'New-Item -ItemType Directory -Force -Path "C:\ProgramData\NetTruder\transcripts" | Out-Null'
$enableAsr = 'Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c,be9ba2d9-53ea-4cdc-84e5-9b1eeee46550,01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions AuditMode,AuditMode,AuditMode'

$fixCmdline = @(
    'Enable Audit Process Creation and the command-line inclusion policy.',
    'Deploy Sysmon Event ID 1 if process creation auditing is not managed centrally.',
    'Re-run the inventory and confirm 4688 or Sysmon 1 matched a probe.'
)
$fixScriptBlock = @(
    'Enable EnableScriptBlockLogging so Event ID 4104 records script text.',
    'Forward the PowerShell operational channel to a central collector.',
    'Re-run the inventory and confirm 4104 matched the marker token.'
)
$fixModuleLog = @(
    'Enable module logging so Event ID 4103 records pipeline execution.',
    'Scope module names if the full stream is too noisy.'
)
$fixTranscription = @(
    'Enable transcription and set an output directory with restricted ACLs.',
    'Forward transcripts or protect the directory with file auditing.'
)
$fixSysmon = @(
    'Install and run Sysmon with a reviewed configuration.',
    'Forward Sysmon 1, 3, 7, 8, 11 and 22 to a central collector.'
)
$fixAmsi = @(
    'Confirm the installed anti-malware product registers an AMSI provider.',
    'Do not remove or replace a provider to make a test pass.'
)
$fixAppLocker = @(
    'Publish AppLocker rules for script and executable control.',
    'Start in audit mode and review the 8003/8004 events before enforcing.'
)
$fixWdac = @(
    'Deploy a WDAC policy from a managed source.',
    'Keep the default Windows policy in place; do not remove it to make a test pass.'
)
$fixAsr = @(
    'Enable the relevant ASR rules in audit mode first.',
    'Review 1121/1122 events, then move the rules to block mode.',
    'Do not disable Defender or ASR to run a test.'
)
$fixWsh = @(
    'If .vbs, .js and .hta are not required, block wscript, cscript and mshta with AppLocker or WDAC.',
    'Do not disable the Windows Script Host globally on developer or admin hosts without a change record.'
)

$controlRows = @(
    New-ControlRow -Id 'cmdline' -Name 'Command line process auditing' -Value $controls.cmdline -Source '4688 command line / Sysmon 1' `
        -Detail 'Records the command line in process creation events. Without it a signed host binary is visible but its arguments are not.' `
        -Fix $fixCmdline -Enable $enableCmdline -Native 'gpedit.msc' -Severity 'high'
    New-ControlRow -Id 'sysmon' -Name 'Sysmon running' -Value $controls.sysmon -Source 'Sysmon 1, 3, 7, 8, 11, 22' `
        -Detail 'Adds image load, network, file and registry telemetry that process creation alone cannot provide.' `
        -Fix $fixSysmon -Native 'services.msc' -Severity 'med'
    New-ControlRow -Id 'scriptblock' -Name 'PowerShell script block logging' -Value $controls.scriptblock -Source '4104 policy' `
        -Detail 'Policy value that records PowerShell script text. This is a policy, not the operational channel state.' `
        -Fix $fixScriptBlock -Enable $enableScriptBlock -Native 'gpedit.msc' -Severity 'high'
    New-ControlRow -Id 'pschannel' -Name 'PowerShell operational channel' -Value $(if ($psLog) { $psLog.enabled } else { $false }) -Source 'Event channel (not a policy)' `
        -Detail 'Channel state only. An enabled channel with no 4104 policy records engine and module events but not script text.' `
        -Fix @('Keep the channel enabled. Configure ScriptBlockLogging separately if content is required.') `
        -Native 'eventvwr.msc' -Severity 'info' -Neutral
    New-ControlRow -Id 'modulelog' -Name 'PowerShell module logging' -Value $controls.modulelog -Source '4103 policy' `
        -Detail 'Records pipeline execution for older PowerShell workloads.' `
        -Fix $fixModuleLog -Enable $enableModuleLog -Native 'gpedit.msc' -Severity 'low'
    New-ControlRow -Id 'transcription' -Name 'PowerShell transcription' -Value $controls.transcription -Source 'Transcription policy' `
        -Detail 'Writes a readable per-session transcript even when script block logging is noisy.' `
        -Fix $fixTranscription -Enable $enableTranscription -Native 'gpedit.msc' -Severity 'low'
    New-ControlRow -Id 'amsi' -Name 'AMSI providers registered' -Value $controls.amsi -Source 'AMSI provider registry' `
        -Detail 'AMSI scans script content before execution, but it does not leave a readable content record.' `
        -Fix $fixAmsi -Native 'windowsdefender://' -Severity 'high'
    New-ControlRow -Id 'applocker' -Name 'AppLocker rules present' -Value $controls.applocker -Source 'SrpV2 policy' `
        -Detail 'Application control for scripts and executables. Rules in audit mode do not block.' `
        -Fix $fixAppLocker -Native 'secpol.msc' -Severity 'med'
    New-ControlRow -Id 'wdac' -Name 'WDAC policy files present' -Value $controls.wdac -Source 'CiPolicies\Active (may include default policy)' `
        -Detail 'Kernel-enforced application control. A default Windows policy may be present without a custom rule set.' `
        -Fix $fixWdac -Native 'eventvwr.msc' -Severity 'med'
    New-ControlRow -Id 'asr' -Name 'Defender ASR block rules' -Value $controls.asr -Source ($asrBlock.ToString() + ' block / ' + $asrAudit.ToString() + ' audit') `
        -Detail 'Attack Surface Reduction rules block or audit common script and Office behaviours.' `
        -Fix $fixAsr -Enable $enableAsr -Native 'windowsdefender://' -Severity 'med'
    New-ControlRow -Id 'wsh' -Name 'Windows Script Host enabled' -Value $controls.wsh -Source 'WSH Settings\Enabled' `
        -Detail 'WSH enabled is a risk on hosts that do not need .vbs, .js or .hta content. This row is safer when off.' `
        -Fix $fixWsh -Native 'secpol.msc' -Severity 'med' -BadWhenOn
)

foreach ($row in $controlRows) {
    $state = if ($row.value) { 'ON ' } else { 'OFF' }
    if ($row.neutral) {
        $color = 'Gray'
    } elseif ($row.value) {
        $color = if ($row.badWhenOn) { 'Yellow' } else { 'Green' }
    } else {
        $color = if ($row.badWhenOn) { 'Green' } else { 'Yellow' }
    }
    Write-Host ('  [{0}] {1,-38} {2}' -f $state, $row.name, $row.source) -ForegroundColor $color
}

Write-Host ('  PowerShell channel: ' + $(if ($psLog) { ('enabled=' + $psLog.enabled + ' records=' + $psLog.records + ' (channel state, not a policy)') } else { 'absent' }))
Write-Host ('  Sysmon log:        ' + $(if ($sysmonLog) { ('enabled=' + $sysmonLog.enabled + ' records=' + $sysmonLog.records) } else { 'not present' }))
Write-Host ('  WSH remote=' + $(if ($null -eq $controls.wshRemote) { 'default' } else { $controls.wshRemote }) + ' trustPolicy=' + $(if ($null -eq $controls.trustPolicy) { 'default' } else { $controls.trustPolicy }))
Write-Host ('  WSL: ' + $(if ($wslState.distros.Count -gt 0) { ($wslState.distros -join ', ') } else { 'none registered' }) + ' | readable=' + $(if ($wslState.available) { ($wslState.readable -join ', ') } else { 'no (' + $wslState.error + ')' }))

Write-Section 'TECHNIQUE INVENTORY'

$results = @()
foreach ($tech in $allTechniques) {
    $platform = [string]$tech.platform
    $sourceReview = ([string]$tech.method -eq 'Source Review')
    $present = $false
    $resolved = ''
    $presenceNote = ''

    if ($sourceReview) {
        # A source-review subject is not a host binary. It has no presence,
        # signature or telemetry gap to score.
        $present = $null
        $presenceNote = 'source-review subject in the local study copy; not a host binary'
    } elseif ($platform -eq 'linux') {
        $pres = Resolve-LinuxPresence -Tech $tech -Wsl $wslState
        $present = $pres.present
        $resolved = $pres.path
        $presenceNote = $pres.note
    } else {
        if ($tech.path -and (Test-Path -LiteralPath $tech.path)) {
            $resolved = [string]$tech.path
        } else {
            $cmd = Get-Command -Name $tech.host -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cmd -and $cmd.Source) { $resolved = [string]$cmd.Source }
        }
        $present = [bool]$resolved
        if ($present) {
            $presenceNote = 'resolved from the host'
        } elseif ($tech.host -eq 'psexesvc.exe') {
            $presenceNote = 'not present; the PsExec service is installed only during use'
        } else {
            $presenceNote = 'not present on this host'
        }
    }

    $sig = [pscustomobject]@{ status = ''; signer = ''; version = '' }
    if ($present -eq $true -and $platform -ne 'linux' -and -not $sourceReview) { $sig = Get-SignatureInfo -Path $resolved }

    $active = @()
    foreach ($c in @($tech.controls)) {
        switch ([string]$c) {
            'cmdline'     { if ($controls.cmdline) { $active += 'cmdline' } }
            'sysmon'      { if ($controls.sysmon) { $active += 'sysmon' } }
            'scriptblock' { if ($controls.scriptblock) { $active += 'scriptblock' } }
            'modulelog'   { if ($controls.modulelog) { $active += 'modulelog' } }
            'transcription' { if ($controls.transcription) { $active += 'transcription' } }
            'amsi'        { if ($controls.amsi) { $active += 'amsi' } }
            'applocker'   { if ($controls.applocker) { $active += 'applocker' } }
            'wdac'        { if ($controls.wdac) { $active += 'wdac' } }
            'asr'         { if ($controls.asr) { $active += 'asr' } }
        }
    }

    $processSignal = ($controls.cmdline -or $controls.sysmon)
    $contentSignal = ($controls.scriptblock -or $controls.amsi)
    $needs = @($tech.needs)
    if ($sourceReview) {
        $gap = 'NOT EVALUATED'
    } elseif ($platform -eq 'linux') {
        if ($present -eq $null) { $gap = 'NOT EVALUATED' }
        else { $gap = 'LINUX GAP' }
    } elseif (-not $processSignal) {
        $gap = 'BLIND'
    } elseif (($needs -contains 'content') -and -not $contentSignal) {
        $gap = 'CONTENT GAP'
    } elseif (($needs -contains 'network') -and -not $controls.sysmon) {
        $gap = 'NETWORK GAP'
    } else {
        $gap = 'OK'
    }

    # The exact measured facts behind the label, so the score can be audited
    # instead of taken on faith. Channel state is kept separate from policy.
    $basis = ('platform[{0}] process[4688-cmdline={1} sysmon={2}] content[4104-policy={3} amsi={4}] channel[ps-operational={5}] presence[{6}]' -f `
        $platform, `
        $(if ($controls.cmdline) { 'on' } else { 'off' }), `
        $(if ($controls.sysmon) { 'on' } else { 'off' }), `
        $(if ($controls.scriptblock) { 'on' } else { 'off' }), `
        $(if ($controls.amsi) { 'on' } else { 'off' }), `
        $(if ($psLog -and $psLog.enabled) { 'enabled' } else { 'off' }), `
        $(if ($present -eq $null) { 'not evaluated' } else { [string]$present }))

    # Observed defensive blocks for this technique, carried through to the
    # console so a blocked vector is visible next to the coverage label.
    $techBlocks = @()
    if ($blocksById.ContainsKey([string]$tech.id)) {
        $techBlocks = @($blocksById[[string]$tech.id])
    }

    $results += [pscustomobject]@{
        id           = [string]$tech.id
        name         = [string]$tech.name
        host         = [string]$tech.host
        family       = [string]$tech.family
        platform     = $platform
        group        = [string]$tech.group
        method       = [string]$tech.method
        catalog      = [string]$tech.catalog
        risk         = [string]$tech.risk
        path         = $resolved
        present      = $present
        presenceNote = $presenceNote
        signature    = [string]$sig.status
        signer       = [string]$sig.signer
        version      = [string]$sig.version
        signals      = ($active -join ',')
        gap          = $gap
        basis        = $basis
        needs        = @($tech.needs)
        abuse        = [string]$tech.abuse
        detection    = [string]$tech.detection
        hardening    = @($tech.hardening)
        # Enrichment from the catalogs. Carried through so the console can
        # show the event chain, command matches, ASR rules and egress watch
        # without duplicating the catalog in two places.
        tree         = @($tech.tree)
        cmd          = $tech.cmd
        asr          = @($tech.asr)
        net          = $tech.net
        fix          = @($tech.fix)
        blocks       = $techBlocks
    }
}

Write-Host ('  {0,-11} {1,-14} {2,-7} {3,-12} {4,-13} {5}' -f 'ID', 'HOST', 'PRESENT', 'SIGNATURE', 'GAP', 'ACTIVE')
foreach ($r in $results) {
    $presentText = if ($r.present -eq $null) { 'n/e' } elseif ($r.present) { 'yes' } else { 'no' }
    $sigText = $r.signature
    if ($sigText.Length -gt 11) { $sigText = $sigText.Substring(0, 11) }
    Write-Host ('  {0,-11} {1,-14} {2,-7} {3,-12} {4,-13} {5}' -f $r.id, $r.host, $presentText, $sigText, $r.gap, $r.signals)
}

Write-Section 'OBSERVED BLOCKS'

if ($allBlocks.Count -eq 0) {
    Write-Host '  No block register loaded.' -ForegroundColor DarkGray
} else {
    foreach ($b in $allBlocks) {
        Write-Host ('  [' + $b.id + '] ' + $b.tech + ' ' + $b.technique + ' - ' + $b.kind + ' - ' + $b.result) -ForegroundColor Green
        Write-Host ('          ' + $b.teaches)
    }
    Write-Host '  A block is a positive control result, not a coverage pass. No bypass was attempted.' -ForegroundColor DarkGray
}

Write-Section 'MARKER PROBES'

$elevation = [pscustomobject]@{
    elevated = $session.tokenElevated
    tokenElevated = $session.tokenElevated
    adminGroup = $session.adminGroup
    elevationType = $session.elevationType
    integrity = $session.integrity
    probeError = $session.probeError
    user = ($env:USERDOMAIN + '\' + $env:USERNAME)
    securityReadable = $false
    securityError = ''
    securityHint = ''
    privilegePresent = $session.privilegePresent
    privilegeEnabled = $session.privilegeEnabled
    auditpolReadable = $false
    auditpolError = ''
    auditpolHint = ''
    privilegeAttempted = $false
    privilegeAttemptResult = $null
    sysmonReadable = $false
    sysmonError = ''
}

try {
    $apText = (& auditpol.exe /get /subcategory:"Process Creation" 2>$null | Out-String)
    if ($LASTEXITCODE -eq 0) {
        $elevation.auditpolReadable = $true
    } else {
        $elevation.auditpolError = ('auditpol exit ' + $LASTEXITCODE)
        if ($LASTEXITCODE -eq 1314) {
            $elevation.auditpolHint = 'auditpol needs SeSecurityPrivilege / Manage auditing and security log. This is expected when the token is not elevated or the privilege was removed by policy.'
        } else {
            $elevation.auditpolHint = 'auditpol could not read the Process Creation subcategory. The exit code is recorded verbatim; no elevation assumption is made.'
        }
    }
} catch {
    $elevation.auditpolError = $_.Exception.Message
    $elevation.auditpolHint = 'auditpol could not be started. The error is recorded verbatim.'
}

$secRead = Test-LogReadable -Name 'Security'
$elevation.securityReadable = $secRead.accessible
if (-not $secRead.accessible) {
    $elevation.privilegeAttempted = $true
    $elevation.privilegeAttemptResult = Enable-SecurityPrivilege
    if ([string]$elevation.privilegeAttemptResult -match '^enabled') {
        # Re-read the privilege state and the log after the in-process enable.
        $after = Get-TokenDiagnostics
        $elevation.privilegePresent = $after.privilegePresent
        $elevation.privilegeEnabled = $after.privilegeEnabled
        $secRead = Test-LogReadable -Name 'Security'
        $elevation.securityReadable = $secRead.accessible
    }
}
if (-not $secRead.accessible) { $elevation.securityError = $secRead.error }
$elevation.securityHint = Get-ElevationHint -E $elevation
$secProbe = Get-RecentEventCount -LogName 'Security' -Id 4688 -Minutes 5

$sysRead = Test-LogReadable -Name 'Microsoft-Windows-Sysmon/Operational'
$elevation.sysmonReadable = $sysRead.accessible
if (-not $sysRead.accessible) { $elevation.sysmonError = $sysRead.error }
$sysmonProbe = Get-RecentEventCount -LogName 'Microsoft-Windows-Sysmon/Operational' -Id 1 -Minutes 5

$markerResults = @()
$measuredProcess = $null
$measuredContent = $null
$processSource = ''
$contentSource = ''
$telemetryDelta = [pscustomobject]@{
    ran = $false
    measuredProcess = $null
    measuredContent = $null
    processSource = ''
    contentSource = ''
    elevation = $elevation
    sec4688 = [pscustomobject]@{ accessible = $false; before = 0; after = 0; delta = $null; matched = 0; verdict = 'Probes were not run.' }
    sysmon1 = [pscustomobject]@{ accessible = $false; matched = 0; verdict = 'Probes were not run.' }
    ps4104 = [pscustomobject]@{ accessible = $false; before = 0; after = 0; delta = $null; matched = 0; verdict = 'Probes were not run.' }
}

if (-not $RunMarkerProbes) {
    Write-Host '  Skipped. Add -RunMarkerProbes -Yes to run the inert marker scripts.' -ForegroundColor DarkGray
} elseif (-not $Yes) {
    Write-Host '  Refused: marker probes need -RunMarkerProbes -Yes together.' -ForegroundColor Yellow
} else {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    $env:NETTRUDER_LAB_DIR = $OutDir
    $markerLog = Join-Path $OutDir 'markers.log'
    $probeDir = Join-Path $PSScriptRoot 'probes'
    $markerList = @(
        [pscustomobject]@{ name = 'wsh-vbs';    host = (Join-Path $env:SystemRoot 'System32\wscript.exe'); args = ('"' + (Join-Path $probeDir 'marker.vbs') + '"') }
        [pscustomobject]@{ name = 'wsh-js';     host = (Join-Path $env:SystemRoot 'System32\cscript.exe'); args = ('//nologo "' + (Join-Path $probeDir 'marker.js') + '"') }
        [pscustomobject]@{ name = 'hta';        host = (Join-Path $env:SystemRoot 'System32\mshta.exe');   args = ('"' + (Join-Path $probeDir 'marker.hta') + '"') }
        [pscustomobject]@{ name = 'powershell'; host = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'); args = ('-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $probeDir 'marker.ps1') + '"') }
    )

    $seen = 0
    if (Test-Path -LiteralPath $markerLog) { $seen = @(Get-Content -LiteralPath $markerLog).Count }

    $sec4688Before = Get-RecentEventCount -LogName 'Security' -Id 4688 -Minutes 5
    $ps4104Before = Get-RecentEventCount -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104 -Minutes 5
    $probeStart = (Get-Date).AddSeconds(-2)

    foreach ($m in $markerList) {
        $item = [pscustomobject]@{ probe = $m.name; host = [IO.Path]::GetFileName($m.host); executed = $false; marker = $false; error = '' }
        try {
            if (-not (Test-Path -LiteralPath $m.host)) { throw 'host not found' }
            $proc = Start-Process -FilePath $m.host -ArgumentList $m.args -PassThru -ErrorAction Stop
            $item.executed = $true
            if (-not $proc.WaitForExit(8000)) {
                try { $proc.Kill() } catch { }
                $item.error = 'timed out'
            }
            $now = 0
            if (Test-Path -LiteralPath $markerLog) { $now = @(Get-Content -LiteralPath $markerLog).Count }
            if ($now -gt $seen) { $item.marker = $true; $seen = $now }
        } catch {
            $item.error = $_.Exception.Message
        }
        $markerResults += $item
        Write-Host ('  {0,-12} executed={1,-6} marker={2} {3}' -f $item.probe, $item.executed, $item.marker, $item.error)
    }

    Write-Host '  Now inspect 4688, Sysmon 1, 4104 and the AMSI/Defender logs to see which probes left telemetry.' -ForegroundColor DarkGray

    $sec4688After = Get-RecentEventCount -LogName 'Security' -Id 4688 -Minutes 6
    $ps4104After = Get-RecentEventCount -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104 -Minutes 6

    $d4688 = $null
    if ($sec4688Before.accessible -and $sec4688After.accessible) { $d4688 = $sec4688After.count - $sec4688Before.count }
    $d4104 = $null
    if ($ps4104Before.accessible -and $ps4104After.accessible) { $d4104 = $ps4104After.count - $ps4104Before.count }

    $probeHosts = @($markerList | ForEach-Object { $_.host })
    $secHits = Get-ProbeProcessHits -Since $probeStart -Hosts $probeHosts
    $sysHits = Get-SysmonProcessHits -Since $probeStart -Hosts $probeHosts
    $psHits = Get-ContentProbeHits -Since $probeStart -Token 'NWPROBE-4104-CONTENT-MARKER'

    $secChannelReadable = [bool]$elevation.securityReadable
    $secAccessible = [bool]($secChannelReadable -and $secHits.accessible)
    $verdict4688 = ''
    if (-not $secChannelReadable) {
        # A filtered -FilterHashtable query can return "no events" without
        # proving channel read access. The direct channel read is authoritative,
        # so do not let a zero-match filter turn an unreadable log into a clean
        # result.
        $verdict4688 = ('Security channel not readable by this session (tokenElevated={0}, adminGroup={1}). Direct read error: {2} {3}' -f $elevation.tokenElevated, $elevation.adminGroup, $elevation.securityError, $elevation.securityHint)
        if ($elevation.privilegeAttempted) {
            $verdict4688 = $verdict4688 + (' SeSecurityPrivilege enable attempted={0}, present={1}, enabled={2}.' -f $elevation.privilegeAttemptResult, $elevation.privilegePresent, $elevation.privilegeEnabled)
        }
        if ($secHits.error) {
            $verdict4688 = $verdict4688 + (' Filtered 4688 query also returned: {0}' -f $secHits.error)
        }
        if ($sysHits.accessible) {
            if ($sysHits.hits -ge 1) { $verdict4688 = $verdict4688 + (' Sysmon 1 matched the probe processes (+{0}); process creation is recorded by Sysmon even though 4688 is unavailable.' -f $sysHits.hits) }
            else { $verdict4688 = $verdict4688 + ' Sysmon 1 is readable but matched none of the probe processes.' }
        } else {
            $verdict4688 = $verdict4688 + (' Sysmon 1 unavailable: {0}' -f $sysHits.error)
        }
    } elseif ($secHits.accessible) {
        if ($secHits.hits -ge 1) { $verdict4688 = ('4688 events matched the probe processes (+{0}); process creation is being recorded.' -f $secHits.hits) }
        else { $verdict4688 = 'No 4688 event matched any of the four probe processes; process creation auditing is not recording them.' }
    } else {
        $verdict4688 = ('Security 4688 query failed even though the channel read succeeded: ' + $secHits.error)
    }

    $verdictSysmon = 'Sysmon 1 was not readable.'
    if ($sysHits.accessible) {
        if ($sysHits.hits -ge 1) { $verdictSysmon = ('Sysmon 1 matched the probe processes (+{0}).' -f $sysHits.hits) }
        else { $verdictSysmon = 'Sysmon 1 is readable but matched none of the probe processes.' }
    } else {
        $verdictSysmon = ('Sysmon 1 unavailable: ' + $sysHits.error)
    }

    $verdict4104 = 'PowerShell operational channel not readable; content proof is unavailable.'
    if ($psHits.accessible) {
        if ($psHits.hits -ge 1) { $verdict4104 = ('4104 events matched the marker script token (+{0}); script content is being recorded.' -f $psHits.hits) }
        else { $verdict4104 = 'No 4104 event contained the marker script token; script block logging is not recording marker.ps1 content. The channel can still be enabled while the 4104 policy is off.' }
    } else {
        $verdict4104 = ('PowerShell operational channel not readable: ' + $psHits.error)
    }

    $telemetryDelta = [pscustomobject]@{
        ran = $true
        sec4688 = [pscustomobject]@{ accessible = $secAccessible; before = $(if ($secAccessible) { $sec4688Before.count } else { 0 }); after = $(if ($secAccessible) { $sec4688After.count } else { 0 }); delta = $(if ($secAccessible) { $d4688 } else { $null }); matched = $(if ($secAccessible) { $secHits.hits } else { 0 }); verdict = $verdict4688 }
        sysmon1 = [pscustomobject]@{ accessible = $sysHits.accessible; matched = $sysHits.hits; verdict = $verdictSysmon }
        ps4104 = [pscustomobject]@{ accessible = $psHits.accessible; before = $ps4104Before.count; after = $ps4104After.count; delta = $d4104; matched = $psHits.hits; verdict = $verdict4104 }
        elevation = $elevation
        processSource = ''
        contentSource = ''
        measuredProcess = $null
        measuredContent = $null
    }

    Write-Host ('  4688 proof: ' + $verdict4688) -ForegroundColor $(if ($secAccessible -and $secHits.hits -ge 1) { 'Green' } else { 'Yellow' })
    Write-Host ('  Sysmon proof: ' + $verdictSysmon) -ForegroundColor $(if ($sysHits.accessible -and $sysHits.hits -ge 1) { 'Green' } else { 'Yellow' })
    Write-Host ('  4104 proof: ' + $verdict4104) -ForegroundColor $(if ($psHits.accessible -and $psHits.hits -ge 1) { 'Green' } else { 'Yellow' })

    # A measured answer beats a policy reading. A readable log with zero
    # matched probes is still a measured result (the signal did not record
    # the test), while an unreadable log leaves the label configuration-derived.
    if ($secAccessible) {
        $measuredProcess = ($secHits.hits -ge 1)
        $processSource = 'Security 4688'
    } elseif ($sysHits.accessible) {
        $measuredProcess = ($sysHits.hits -ge 1)
        $processSource = 'Sysmon 1'
    }
    if ($psHits.accessible) {
        $measuredContent = ($psHits.hits -ge 1)
        $contentSource = 'PowerShell 4104'
    }
    $telemetryDelta.measuredProcess = $measuredProcess
    $telemetryDelta.measuredContent = $measuredContent
    $telemetryDelta.processSource = $processSource
    $telemetryDelta.contentSource = $contentSource

    $mpText = 'n/a'
    if ($null -ne $measuredProcess) { if ($measuredProcess) { $mpText = 'on' } else { $mpText = 'off' } }
    $mcText = 'n/a'
    if ($null -ne $measuredContent) { if ($measuredContent) { $mcText = 'on' } else { $mcText = 'off' } }
    $measText = ('measured[4688=' + $mpText + ' sysmon=' + $(if ($sysHits.accessible) { if ($sysHits.hits -ge 1) { 'on' } else { 'off' } } else { 'n/a' }) + ' 4104=' + $mcText + ' sources=' + $processSource + '/' + $contentSource + ']')

    foreach ($r in $results) {
        # Linux entries are not executed, and Source Review entries are static
        # study subjects rather than host binaries. Neither can be promoted by
        # a Windows marker probe; keep their original NOT EVALUATED/LINUX GAP.
        if ($r.platform -eq 'linux' -or [string]$r.method -eq 'Source Review') { continue }
        $r.basis = ($r.basis + ' ' + $measText)
        # Reconcile each label with what the probe actually saw. If a signal is
        # demonstrably recording, it must not be called a gap.
        $processOk = ($processSignal -or ($measuredProcess -eq $true))
        $contentOk = ($contentSignal -or ($measuredContent -eq $true))
        if (-not $processOk) {
            $r.gap = 'BLIND'
        } elseif (($r.needs -contains 'content') -and -not $contentOk) {
            $r.gap = 'CONTENT GAP'
        } elseif (($r.needs -contains 'network') -and -not $controls.sysmon) {
            $r.gap = 'NETWORK GAP'
        } else {
            $r.gap = 'OK'
        }
    }
}

Write-Section 'FINDINGS'

$findings = @()
$processSignal = ($controls.cmdline -or $controls.sysmon)
$contentSignal = ($controls.scriptblock -or $controls.amsi)
if (-not $processSignal -and $measuredProcess -ne $true) {
    $detail = 'Enable Audit Process Creation with command line, or deploy Sysmon Event ID 1. Without it, every proxy execution technique in this catalog is effectively invisible.'
    if ($null -eq $measuredProcess) {
        $detail = $detail + ' The probe could not verify this because neither Security 4688 nor Sysmon 1 was readable. Error: ' + $elevation.securityError + ' ' + $elevation.securityHint + ' Label is configuration-derived, not measured.'
    } elseif ($measuredProcess -eq $false) {
        $detail = $detail + ' Confirmed by probe: four processes started and no 4688 or Sysmon 1 event matched them.'
    }
    Add-Finding 'HIGH' 'No process creation telemetry' $detail -Control 'cmdline' -Fix $fixCmdline -Enable $enableCmdline -Native 'gpedit.msc'
}
if (-not $controls.scriptblock -and $measuredContent -ne $true) {
    $detail = 'Enable EnableScriptBlockLogging under HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging so Event ID 4104 records PowerShell content. AMSI scans content but does not leave a readable record of it. The PowerShell operational channel can be enabled while this policy is still off; they are not the same setting.'
    if ($measuredContent -eq $false) {
        $detail = $detail + ' Confirmed by probe: marker.ps1 ran and no 4104 event contained the marker token.'
    } elseif ($null -eq $measuredContent) {
        $detail = $detail + ' The channel was not readable, so the label is configuration-derived.'
    }
    Add-Finding 'HIGH' 'PowerShell script block logging is off' $detail -Control 'scriptblock' -Fix $fixScriptBlock -Enable $enableScriptBlock -Native 'gpedit.msc'
}
if (-not $controls.amsi) {
    Add-Finding 'HIGH' 'No AMSI provider is registered' 'Script content passed to Windows Script Host and PowerShell may not be scanned. Check the AMSI provider registry and the installed anti-malware product.' -Control 'amsi' -Fix $fixAmsi -Native 'windowsdefender://'
}
if ($controls.wsh -and -not $controls.applocker -and -not $controls.wdac) {
    Add-Finding 'MEDIUM' 'Windows Script Host is allowed without an execution policy' 'If .vbs, .js and .hta are not required, block wscript, cscript and mshta with WDAC or AppLocker, or set the WSH Enabled policy to 0. Do not apply this blindly on developer or admin hosts.' -Control 'wsh' -Fix $fixWsh -Native 'secpol.msc'
}
if (-not $controls.sysmon) {
    Add-Finding 'MEDIUM' 'Sysmon is not running' 'Sysmon adds image load, network, file and registry telemetry that process creation alone cannot provide.' -Control 'sysmon' -Fix $fixSysmon -Native 'services.msc'
}
if ($asrTotal -eq 0) {
    Add-Finding 'MEDIUM' 'No Defender ASR rules are configured' 'Start in audit mode with rules for Office child processes, script downloads and executable content from email.' -Control 'asr' -Fix $fixAsr -Enable $enableAsr -Native 'windowsdefender://'
}
if (-not $controls.transcription) {
    Add-Finding 'LOW' 'PowerShell transcription is off' 'Transcription gives a readable per-session record even when script block logging is noisy.' -Control 'transcription' -Fix $fixTranscription -Enable $enableTranscription -Native 'gpedit.msc'
}
if (-not $controls.modulelog) {
    Add-Finding 'LOW' 'PowerShell module logging is off' 'Module logging records pipeline execution for older PowerShell workloads.' -Control 'modulelog' -Fix $fixModuleLog -Enable $enableModuleLog -Native 'gpedit.msc'
}
if ($controls.wshRemote -eq 1) {
    Add-Finding 'LOW' 'Remote Windows Script Host is allowed' 'Set the WSH Remote policy to 0 unless remote script execution is required.' -Control 'wsh' -Fix $fixWsh -Native 'secpol.msc'
}

# Where measurement contradicts a policy reading, say so plainly. A tool that
# only repeats registry values would hide these cases.
if ($measuredProcess -eq $true -and -not $processSignal) {
    Add-Finding 'MEDIUM' 'Process creation telemetry is recording without the expected policy' ('4688 or Sysmon 1 matched the probe processes (+' + $telemetryDelta.sec4688.matched + ') even though the command-line audit value reads off. Source: ' + $processSource + '. Verify which audit subcategory is enabled before relying on the command line field.') -Control 'cmdline' -Fix $fixCmdline -Enable $enableCmdline -Native 'gpedit.msc'
}
if ($measuredContent -eq $true -and -not $controls.scriptblock) {
    Add-Finding 'LOW' 'Script content logging is active without the ScriptBlockLogging policy value' ('4104 events matched the marker script (+' + $telemetryDelta.ps4104.matched + ') while the policy value is absent. Content is being recorded by another mechanism; confirm its scope before relying on it.') -Control 'scriptblock' -Fix $fixScriptBlock -Enable $enableScriptBlock -Native 'gpedit.msc'
}
if ($controls.scriptblock -and $measuredContent -eq $false) {
    Add-Finding 'HIGH' 'Script block logging is configured but not observed' 'The policy reads on, but no 4104 event contained the marker token while marker.ps1 ran. Check the policy scope and the event channel before trusting the setting.' -Control 'scriptblock' -Fix $fixScriptBlock -Enable $enableScriptBlock -Native 'eventvwr.msc'
}

if (-not $elevation.securityReadable -and $elevation.adminGroup -and -not $elevation.tokenElevated) {
    Add-Finding 'MEDIUM' 'Administrator account is running with a filtered token' ('The account is in Administrators, but this process is not elevated (integrity ' + $elevation.integrity + ', elevation type ' + $elevation.elevationType + '). The Security log cannot be read, so 4688 process proof stays configuration-derived. ' + $elevation.securityHint) -Fix @(
        'Close NetTruder and right-click Launch-Elevated.cmd; choose Run as administrator.',
        'Accept the UAC prompt and re-run the coverage inventory with marker probes.',
        'Confirm the ELEVATION proof card shows tokenElevated=yes and adminGroup=yes.',
        'NetTruder never disables UAC and never auto-elevates.'
    ) -Native 'secpol.msc'
}

if ($findings.Count -eq 0) {
    Write-Host '  No high-level gaps found in the controls that were checked.' -ForegroundColor Green
} else {
    foreach ($f in $findings) {
        $color = switch ($f.severity) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Gray' } }
        Write-Host ('  [' + $f.severity + '] ' + $f.title) -ForegroundColor $color
        Write-Host ('          ' + $f.detail)
    }
}

Write-Section 'REPORTS'

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$baseName = 'lolbas-posture-' + $stamp.ToString('yyyyMMdd-HHmmss')
$jsonPath = Join-Path $OutDir ($baseName + '.json')
$mdPath = Join-Path $OutDir ($baseName + '.md')

$groups = @()
foreach ($g in @($results | Group-Object group | Sort-Object Name)) {
    $groups += [pscustomobject]@{ name = [string]$g.Name; count = [int]$g.Count }
}
$platforms = @()
foreach ($p in @($results | Group-Object platform | Sort-Object Name)) {
    $platforms += [pscustomobject]@{ name = [string]$p.Name; count = [int]$p.Count }
}

$report = [pscustomobject]@{
    generated = $stamp.ToString('s')
    host = $env:COMPUTERNAME
    user = ($env:USERDOMAIN + '\' + $env:USERNAME)
    admin = $isAdmin
    adminGroup = $session.adminGroup
    tokenElevated = $session.tokenElevated
    elevationType = $session.elevationType
    integrity = $session.integrity
    windows = $(if ($os) { [string]$os.Caption } else { '' })
    build = $(if ($os) { [string]$os.BuildNumber } else { '' })
    powershell = $PSVersionTable.PSVersion.ToString()
    catalog = $catalogVersionText
    catalogs = $catalogs
    groups = $groups
    platforms = $platforms
    controls = $controls
    controlRows = $controlRows
    asr = [pscustomobject]@{ total = $asrTotal; block = $asrBlock; audit = $asrAudit }
    amsiProviders = $amsiProviders.Count
    wshRemote = $controls.wshRemote
    trustPolicy = $controls.trustPolicy
    powershellLog = $psLog
    sysmonLog = $sysmonLog
    wsl = $wslState
    techniques = $results
    probes = $markerResults
    telemetryDelta = $telemetryDelta
    blocks = @($allBlocks)
    blockCount = @($allBlocks).Count
    proof = [pscustomobject]@{
        method = 'Registry, service, file and event-log inventory, plus an optional before/after probe window that counts 4688, Sysmon 1 and 4104 events.'
        measured = $stamp.ToString('s')
        elevation = $elevation
        processSource = $processSource
        contentSource = $contentSource
        thirdPartyEdr = 'not evaluated'
        caveat = 'Gap labels describe native Windows telemetry only. A BLIND label means the native signal the technique depends on is not configured here; it is measured where 4688 or Sysmon 1 is readable and configuration-derived otherwise. A third-party EDR or proxy can still record what this report marks BLIND. Linux entries are presence-checked only through a readable WSL filesystem and are not executed. HEVD Source Review entries are static study subjects and are always NOT EVALUATED.'
    }
    findings = $findings
}

try {
    $report | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    Write-Host ('  JSON ' + $jsonPath)
} catch {
    Write-Host ('  Could not write JSON: ' + $_.Exception.Message) -ForegroundColor Red
}

$md = New-Object System.Collections.Generic.List[string]
$md.Add('# NetTruder LOLBAS posture report')
$md.Add('')
$md.Add('- Generated: ' + $stamp.ToString('yyyy-MM-dd HH:mm:ss'))
$md.Add('- Host: ' + $env:COMPUTERNAME + ' (' + $(if ($os) { $os.Caption } else { 'unknown' }) + ' build ' + $(if ($os) { $os.BuildNumber } else { '?' }) + ')')
$md.Add('- User: ' + $env:USERDOMAIN + '\' + $env:USERNAME + ' (admin: ' + $isAdmin + ')')
$md.Add('- Catalogs: ' + $catalogVersionText)
$md.Add('- PowerShell: ' + $PSVersionTable.PSVersion.ToString())
$md.Add('- WSL: ' + $(if ($wslState.distros.Count -gt 0) { ($wslState.distros -join ', ') } else { 'none registered' }) + '; readable: ' + $(if ($wslState.available) { ($wslState.readable -join ', ') } else { 'no (' + $wslState.error + ')' }))
$md.Add('')
$md.Add('## Controls')
$md.Add('')
$md.Add('| Control | State | Source | Detail |')
$md.Add('|---|---|---|---|')
foreach ($row in $controlRows) {
    $md.Add('| ' + $row.name + ' | ' + $(if ($row.value) { 'ON' } else { 'OFF' }) + ' | ' + $row.source + ' | ' + $row.detail + ' |')
}
$md.Add('| PowerShell channel | ' + $(if ($psLog) { 'enabled=' + $psLog.enabled + ', records=' + $psLog.records } else { 'absent' }) + ' | Event channel (not a policy) | Channel state is not ScriptBlockLogging policy. |')
$md.Add('| Sysmon log | ' + $(if ($sysmonLog) { 'enabled=' + $sysmonLog.enabled + ', records=' + $sysmonLog.records } else { 'not present' }) + ' | Event log | |')
$md.Add('')
$md.Add('### Control remediation')
$md.Add('')
foreach ($row in $controlRows) {
    if (-not $row.value -or $row.badWhenOn) {
        $md.Add('#### ' + $row.name)
        $md.Add('')
        foreach ($line in @($row.fix)) { $md.Add('- ' + $line) }
        if ($row.enable) {
            $md.Add('')
            $md.Add('```powershell')
            foreach ($line in ($row.enable -split "`n")) { $md.Add($line) }
            $md.Add('```')
        }
        $md.Add('')
    }
}
$md.Add('NetTruder never turns a control off. The actions above enable or harden a control and require an administrator.')
$md.Add('')
$md.Add('## Techniques by group')
$md.Add('')
foreach ($g in $groups) {
    $md.Add('### ' + $g.name + ' (' + $g.count + ')')
    $md.Add('')
    $md.Add('| ID | Name | Host | Platform | Present | Signature | Gap | Basis | Active controls |')
    $md.Add('|---|---|---|---|---|---|---|---|---|')
    foreach ($r in @($results | Where-Object { $_.group -eq $g.name })) {
        $presentText = if ($r.present -eq $null) { 'not evaluated' } elseif ($r.present) { 'yes' } else { 'no' }
        $md.Add('| ' + $r.id + ' | ' + $r.name + ' | ' + $r.host + ' | ' + $r.platform + ' | ' + $presentText + ' | ' + $r.signature + ' | ' + $r.gap + ' | ' + $r.basis + ' | ' + $r.signals + ' |')
    }
    $md.Add('')
}
$md.Add('## Observed defensive blocks')
$md.Add('')
if ($allBlocks.Count -eq 0) {
    $md.Add('No block register was loaded.')
} else {
    $md.Add('A block is a positive control result, not a coverage pass. It says nothing about variants that were not attempted, and no bypass was attempted.')
    $md.Add('')
    foreach ($b in $allBlocks) {
        $md.Add('### ' + $b.id + ' - ' + $b.tech + ' ' + $b.technique)
        $md.Add('')
        $md.Add('- Kind: ' + $b.kind + ' (' + $b.product + ')')
        $md.Add('- Date: ' + $b.date)
        $md.Add('- Vector: ' + $b.vector)
        $md.Add('- Result: ' + $b.result)
        $md.Add('- Signal: ' + $b.signal)
        $md.Add('- Scope: ' + $b.scope)
        $md.Add('- Teaches: ' + $b.teaches)
        $md.Add('- Detect: ' + $b.detect)
        $md.Add('')
    }
}
$md.Add('## Telemetry proof')
$md.Add('')
if (-not $telemetryDelta.ran) {
    $md.Add('Marker probes were not run, so there is no empirical before/after check. The gap labels above come from configuration only.')
} else {
    $md.Add('| Signal | Accessible | Before | After | Delta | Matched | Verdict |')
    $md.Add('|---|---|---|---|---|---|---|')
    $md.Add('| Security 4688 | ' + $telemetryDelta.sec4688.accessible + ' | ' + $telemetryDelta.sec4688.before + ' | ' + $telemetryDelta.sec4688.after + ' | ' + $telemetryDelta.sec4688.delta + ' | ' + $telemetryDelta.sec4688.matched + ' | ' + $telemetryDelta.sec4688.verdict + ' |')
    $md.Add('| Sysmon 1 | ' + $telemetryDelta.sysmon1.accessible + ' | n/a | n/a | n/a | ' + $telemetryDelta.sysmon1.matched + ' | ' + $telemetryDelta.sysmon1.verdict + ' |')
    $md.Add('| PowerShell 4104 | ' + $telemetryDelta.ps4104.accessible + ' | ' + $telemetryDelta.ps4104.before + ' | ' + $telemetryDelta.ps4104.after + ' | ' + $telemetryDelta.ps4104.delta + ' | ' + $telemetryDelta.ps4104.matched + ' | ' + $telemetryDelta.ps4104.verdict + ' |')
    $md.Add('')
    $md.Add('Matched counts only events attributable to the probes: 4688 or Sysmon 1 events whose image is one of the four probe hosts, and 4104 events whose text contains the marker script token. The before/after columns are broad counts kept for context; unrelated activity (including this tool) can move them.')
    $md.Add('')
    $md.Add('Elevation: tokenElevated=' + $elevation.tokenElevated + ', adminGroup=' + $elevation.adminGroup + ', integrity=' + $elevation.integrity + ', elevationType=' + $elevation.elevationType + ', user=' + $elevation.user + ', Security readable=' + $elevation.securityReadable + ', Sysmon readable=' + $elevation.sysmonReadable + ', SeSecurityPrivilege present=' + $elevation.privilegePresent + ', enabled=' + $elevation.privilegeEnabled + ', enable attempt=' + $elevation.privilegeAttempted + ' result=' + $elevation.privilegeAttemptResult + '.')
    if ($elevation.securityHint) { $md.Add('Elevation diagnosis: ' + $elevation.securityHint) }
    if ($elevation.securityError) { $md.Add('Security error: ' + $elevation.securityError) }
    if ($elevation.auditpolError) { $md.Add('auditpol error: ' + $elevation.auditpolError + ' ' + $elevation.auditpolHint) }
    if ($elevation.probeError) { $md.Add('Token probe note: ' + $elevation.probeError) }
}
$md.Add('')
$md.Add('Caveat: these labels cover native Windows telemetry only. A BLIND label means the native signal is not configured here; it is a measured result only where 4688 or Sysmon 1 is readable, and configuration-derived otherwise. A third-party EDR or proxy can still record activity this report marks BLIND. Linux entries are never executed and are reported as not evaluated when WSL is unreadable. HEVD Source Review entries are static study subjects and are always NOT EVALUATED.')
$md.Add('')
$md.Add('## Marker probes')
$md.Add('')
if ($markerResults.Count -eq 0) {
    $md.Add('Not run.')
} else {
    $md.Add('| Probe | Host | Executed | Marker written | Error |')
    $md.Add('|---|---|---|---|---|')
    foreach ($m in $markerResults) {
        $md.Add('| ' + $m.probe + ' | ' + $m.host + ' | ' + $m.executed + ' | ' + $m.marker + ' | ' + $m.error + ' |')
    }
}
$md.Add('')
$md.Add('## Findings')
$md.Add('')
if ($findings.Count -eq 0) {
    $md.Add('No high-level gaps found in the controls that were checked.')
} else {
    foreach ($f in $findings) {
        $md.Add('### [' + $f.severity + '] ' + $f.title)
        $md.Add('')
        $md.Add($f.detail)
        $md.Add('')
        if ($f.control) { $md.Add('Control: ' + $f.control) }
        foreach ($line in @($f.fix)) { $md.Add('- ' + $line) }
        if ($f.enable) {
            $md.Add('')
            $md.Add('```powershell')
            foreach ($line in ($f.enable -split "`n")) { $md.Add($line) }
            $md.Add('```')
        }
        $md.Add('')
    }
}
$md.Add('')
$md.Add('## Notes')
$md.Add('')
$md.Add('This report is read-only output. NetTruder did not change any security setting.')
$md.Add('Absence of telemetry in this report is a coverage finding, not proof that a technique will succeed.')
$md.Add('NetTruder never offers to turn a security control off. Enable and harden actions require an administrator.')

try {
    $md | Set-Content -LiteralPath $mdPath -Encoding UTF8
    Write-Host ('  MD   ' + $mdPath)
} catch {
    Write-Host ('  Could not write Markdown: ' + $_.Exception.Message) -ForegroundColor Red
}

Write-Host ''
Write-Host 'Done. Nothing was modified.' -ForegroundColor Green
