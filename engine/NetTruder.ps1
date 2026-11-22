<#
    NetTruder 1.1.0
    Network sweep + host-based IDS + reversible IPS + local ops terminal for Windows.

    Safety model
    -------------
    * Read-only by default. Nothing is blocked or changed unless you ask for it.
    * IPS uses only its own firewall rules, prefixed "NetTruder-IPS-". It never
      edits profiles, services, Defender, Windows Update or existing rules.
    * Every rule carries an expiry and is removed automatically.
    * Never blocks the local machine, its default gateway, or its DNS servers.
    * Every action is appended to an audit log under %LOCALAPPDATA%\NetTruder.
    * The terminal runs local commands only, in the current user context, and
      records the command line in the audit log. No remote shell, no listener.
#>
[CmdletBinding()]
param(
    [ValidateSet('status', 'probe', 'rules', 'scan', 'watch', 'block', 'unblock', 'release', 'expire', 'shell', 'processes', 'kill', 'research', 'webscan', 'codeaudit', 'coderead', 'codewrite', 'flow', 'investigate', 'netinv', 'triage', 'av', 'datacheck', 'datapurge', 'pslog', 'claimcheck')]
    [string]$Action = 'status',

    [string]$RequestFile = '',
    [string]$RunId = 'adhoc',
    [string]$Targets = '',
    [string]$Ports = '',
    [string]$Profile = 'common',
    [int]$TimeoutMs = 700,
    [int]$IntervalSec = 2,
    [int]$SampleSec = 0,
    [int]$MaxFlows = 400,
    [string]$RemoteIp = '',
    [int]$DurationMin = 10,
    [string]$CmdLine = '',
    [string]$WorkDir = '',
    [int]$MaxSeconds = 900,
    [int]$ProcId = 0,
    [string]$Url = '',
    [string]$Path = '',
    [string]$Query = '',
    [string]$ItemId = '',
    [string]$Decision = '',
    [int]$Hours = 72,
    [int]$RetentionDays = 30,
    [string]$ClaimText = '',
    [switch]$IncludeAudit,
    [switch]$AckRisk,
    [switch]$Probes,
    [string]$LabDir = '',
    [string]$ContentFile = '',
    [switch]$AutoBlock,
    [switch]$AllowPublic,
    [switch]$BrowserHistory,
    [switch]$Yes
)

# The HTA writes a JSON request file rather than a long command line, so targets
# and terminal commands never have to survive cmd/PowerShell quoting.
if (-not [string]::IsNullOrWhiteSpace($RequestFile) -and (Test-Path -LiteralPath $RequestFile)) {
    try {
        $req = Get-Content -LiteralPath $RequestFile -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($req.action) { $Action = [string]$req.action }
        if ($req.runId) { $RunId = [string]$req.runId }
        if ($null -ne $req.targets) { $Targets = [string]$req.targets }
        if ($null -ne $req.ports) { $Ports = [string]$req.ports }
        if ($req.profile) { $Profile = [string]$req.profile }
        if ($null -ne $req.timeoutMs) { $TimeoutMs = [int]$req.timeoutMs }
        if ($null -ne $req.intervalSec) { $IntervalSec = [int]$req.intervalSec }
        if ($null -ne $req.sampleSec) { $SampleSec = [int]$req.sampleSec }
        if ($null -ne $req.maxFlows) { $MaxFlows = [int]$req.maxFlows }
        if ($null -ne $req.remoteIp) { $RemoteIp = [string]$req.remoteIp }
        if ($null -ne $req.durationMin) { $DurationMin = [int]$req.durationMin }
        if ($null -ne $req.cmdLine) { $CmdLine = [string]$req.cmdLine }
        if ($null -ne $req.workDir) { $WorkDir = [string]$req.workDir }
        if ($null -ne $req.maxSeconds) { $MaxSeconds = [int]$req.maxSeconds }
        if ($null -ne $req.procId) { $ProcId = [int]$req.procId }
        if ($null -ne $req.url) { $Url = [string]$req.url }
        if ($null -ne $req.path) { $Path = [string]$req.path }
        if ($null -ne $req.query) { $Query = [string]$req.query }
        if ($null -ne $req.itemId) { $ItemId = [string]$req.itemId }
        if ($null -ne $req.decision) { $Decision = [string]$req.decision }
        if ($null -ne $req.claimText) { $ClaimText = [string]$req.claimText }
        if ($null -ne $req.hours) { $Hours = [int]$req.hours }
        if ($null -ne $req.retentionDays) { $RetentionDays = [int]$req.retentionDays }
        if ($null -ne $req.includeAudit) { $IncludeAudit = [bool]$req.includeAudit }
        if ($null -ne $req.ackRisk) { $AckRisk = [bool]$req.ackRisk }
        if ($null -ne $req.probes) { $Probes = [bool]$req.probes }
        if ($null -ne $req.labDir) { $LabDir = [string]$req.labDir }
        if ($null -ne $req.contentFile) { $ContentFile = [string]$req.contentFile }
        if ($null -ne $req.autoBlock) { $AutoBlock = [bool]$req.autoBlock }
        if ($null -ne $req.allowPublic) { $AllowPublic = [bool]$req.allowPublic }
        if ($null -ne $req.browserHistory) { $BrowserHistory = [bool]$req.browserHistory }
        if ($null -ne $req.yes) { $Yes = [bool]$req.yes }
        Remove-Item -LiteralPath $RequestFile -Force -ErrorAction SilentlyContinue
    } catch { }
}
$allowedActions = @('status', 'probe', 'rules', 'scan', 'watch', 'block', 'unblock', 'release', 'expire', 'shell', 'processes', 'kill', 'research', 'webscan', 'codeaudit', 'coderead', 'codewrite', 'flow', 'investigate', 'netinv', 'triage', 'av', 'datacheck', 'datapurge', 'pslog', 'claimcheck')
if ($allowedActions -notcontains $Action) { $Action = 'status' }

$ErrorActionPreference = 'Continue'
$script:Version = '1.1.0'

$script:Root = Join-Path $env:LOCALAPPDATA 'NetTruder'
$script:Runs = Join-Path $script:Root 'runs'
$script:Audit = Join-Path $script:Root 'audit'
$script:State = Join-Path $script:Root 'state'
$script:EngineDir = Split-Path -Parent $PSCommandPath
$script:Evt = Join-Path $script:Runs ("{0}.events.ndjson" -f $RunId)
$script:Stop = Join-Path $script:Runs ("{0}.stop" -f $RunId)
$script:Ring = Join-Path $script:State 'ips-journal.json'
$script:Cooldown = @{}
$script:MaxHosts = 512

foreach ($d in @($script:Root, $script:Runs, $script:Audit, $script:State)) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
try { [IO.File]::WriteAllText($script:Evt, '') } catch { }
Remove-Item -LiteralPath $script:Stop -Force -ErrorAction SilentlyContinue
$script:DataMigrated = 0

$script:Profiles = @{
    'common' = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 9200, 11211, 27017)
    'web'    = @(80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000)
    'remote' = @(22, 23, 139, 445, 3389, 5900, 5985, 5986)
    'mail'   = @(25, 110, 143, 465, 587, 993, 995)
    'db'     = @(1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017)
}

$script:ServiceNames = @{
    21 = 'ftp'; 22 = 'ssh'; 23 = 'telnet'; 25 = 'smtp'; 53 = 'dns'; 80 = 'http'; 110 = 'pop3'
    135 = 'rpc'; 139 = 'netbios'; 143 = 'imap'; 443 = 'https'; 445 = 'smb'; 587 = 'smtp-sub'
    993 = 'imaps'; 995 = 'pop3s'; 1080 = 'socks'; 1433 = 'mssql'; 1521 = 'oracle'; 3000 = 'dev-http'
    3306 = 'mysql'; 3389 = 'rdp'; 4444 = 'handler'; 5000 = 'dev-http'; 5432 = 'postgres'
    5900 = 'vnc'; 5985 = 'winrm-http'; 5986 = 'winrm-https'; 6379 = 'redis'; 8000 = 'http-alt'
    8080 = 'http-alt'; 8081 = 'http-alt'; 8443 = 'https-alt'; 8888 = 'http-alt'; 9200 = 'elastic'
    11211 = 'memcached'; 27017 = 'mongodb'
}

function Escape-Ascii {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if ($code -gt 126 -or ($code -lt 32 -and $code -ne 9)) {
            [void]$sb.Append(('\u{0:x4}' -f $code))
        } else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

function Write-Evt {
    param(
        [string]$Kind,
        [string]$Level = 'info',
        [string]$Message = '',
        $Data = $null
    )
    $o = @{ t = (Get-Date).ToString('HH:mm:ss'); k = $Kind; lvl = $Level; m = $Message }
    if ($null -ne $Data) { $o['d'] = $Data }
    try {
        $json = ConvertTo-Json -InputObject $o -Compress -Depth 12
        [IO.File]::AppendAllText($script:Evt, (Escape-Ascii $json) + "`n", [Text.Encoding]::ASCII)
    } catch { }
}

function Write-Audit {
    param([string]$Kind, [string]$Detail, $Data = $null)
    $o = @{ t = (Get-Date).ToUniversalTime().ToString('o'); kind = $Kind; detail = $Detail }
    if ($null -ne $Data) { $o['d'] = $Data }
    $path = Join-Path $script:Audit ("audit-{0}.ndjson" -f (Get-Date).ToString('yyyyMMdd'))
    try {
        $json = ConvertTo-Json -InputObject $o -Compress -Depth 12
        [IO.File]::AppendAllText($path, (Escape-Ascii $json) + "`n", [Text.Encoding]::ASCII)
    } catch { }
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# IsInRole(Administrator) answers "is this token elevated for the Administrator
# role", which is false for a UAC-filtered admin token. Test-AdminGroup answers
# the different question "is the account in Administrators", including the
# deny-only SID that UAC leaves in a filtered token.
function Test-AdminGroup {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        foreach ($g in $id.Groups) {
            if ([string]$g.Value -eq 'S-1-5-32-544') { return $true }
        }
        foreach ($c in $id.Claims) {
            if (([string]$c.Type).ToLower().IndexOf('denyonlysid') -ge 0 -and [string]$c.Value -eq 'S-1-5-32-544') { return $true }
        }
    } catch { }
    return $false
}

function Test-PrivateIp {
    param([string]$Ip)
    $o = $Ip.Split('.')
    if ($o.Count -ne 4) { return $true }
    $a = 0; $b = 0
    [void][int]::TryParse($o[0], [ref]$a)
    [void][int]::TryParse($o[1], [ref]$b)
    if ($a -eq 10) { return $true }
    if ($a -eq 127) { return $true }
    if ($a -eq 0) { return $true }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $true }
    if ($a -eq 192 -and $b -eq 168) { return $true }
    if ($a -eq 169 -and $b -eq 254) { return $true }
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return $true }
    return $false
}

# The console was called NetWatch before 1.1.0. Copy any state, audit and lab
# files that are not already present in the new data root. Copy only: the old
# folder is never deleted or moved, so a rollback stays possible.
function Initialize-DataRoot {
    $legacy = Join-Path $env:LOCALAPPDATA 'NetWatch'
    if (-not (Test-Path -LiteralPath $legacy)) { return 0 }
    if ([string]::Equals($legacy, $script:Root, [StringComparison]::OrdinalIgnoreCase)) { return 0 }
    $copied = 0
    foreach ($sub in @('state', 'audit', 'lab')) {
        $src = Join-Path $legacy $sub
        $dst = Join-Path $script:Root $sub
        if (-not (Test-Path -LiteralPath $src)) { continue }
        try { if (-not (Test-Path -LiteralPath $dst)) { New-Item -ItemType Directory -Path $dst -Force | Out-Null } } catch { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $src -File -ErrorAction SilentlyContinue)) {
            $target = Join-Path $dst $f.Name
            if (Test-Path -LiteralPath $target) { continue }
            try {
                Copy-Item -LiteralPath $f.FullName -Destination $target -ErrorAction Stop
                $copied++
            } catch { }
        }
    }
    return $copied
}

function ConvertTo-IPLong {
    param([string]$Ip)
    $o = $Ip.Split('.')
    if ($o.Count -ne 4) { return [uint32]0 }
    return ([uint32]$o[0] -shl 24) -bor ([uint32]$o[1] -shl 16) -bor ([uint32]$o[2] -shl 8) -bor [uint32]$o[3]
}

function ConvertFrom-IPLong {
    param([uint32]$Value)
    return ('{0}.{1}.{2}.{3}' -f (($Value -shr 24) -band 255), (($Value -shr 16) -band 255), (($Value -shr 8) -band 255), ($Value -band 255))
}

function Get-Rules {
    $p = Join-Path $script:EngineDir 'rules.json'
    if (Test-Path -LiteralPath $p) {
        try { return (Get-Content -LiteralPath $p -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { }
    }
    return [pscustomobject]@{
        version     = 'fallback'
        listenPorts = @()
        remotePorts = @()
        egressWatch = @()
        beacon      = [pscustomobject]@{ minConnections = 6; windowSec = 150; maxJitter = 0.30; minMeanSec = 8; maxMeanSec = 200; sev = 'high' }
        fanout      = [pscustomobject]@{
            distinctHosts = 25; windowSec = 60; sev = 'high'
            browserProcs = @('msedge', 'chrome', 'firefox', 'brave', 'opera', 'vivaldi', 'iexplore')
            browserSev = 'low'; browserHosts = 30
            lateralHosts = 4; lateralSev = 'high'; lateralPorts = '135,139,445,3389,5985,5986,22'
        }
    }
}

function Get-Journal {
    if (-not (Test-Path -LiteralPath $script:Ring)) { return @() }
    try {
        $raw = Get-Content -LiteralPath $script:Ring -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        return @($raw | ConvertFrom-Json)
    } catch { return @() }
}

function Save-Journal {
    param($Items)
    $arr = @($Items)
    try {
        $json = ConvertTo-Json -InputObject $arr -Depth 6
        $enc = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($script:Ring, $json, $enc)
    } catch { }
}

function Test-PortInSpec {
    param([int]$Port, [string]$Spec)
    if ([string]::IsNullOrWhiteSpace($Spec)) { return $true }
    foreach ($part in $Spec.Split(',')) {
        $p = $part.Trim()
        if (-not $p) { continue }
        $dash = $p.IndexOf('-')
        if ($dash -gt 0) {
            $lo = 0
            $hi = 0
            if ([int]::TryParse($p.Substring(0, $dash), [ref]$lo) -and [int]::TryParse($p.Substring($dash + 1), [ref]$hi)) {
                if ($Port -ge $lo -and $Port -le $hi) { return $true }
            }
        } else {
            $v = 0
            if ([int]::TryParse($p, [ref]$v) -and $v -eq $Port) { return $true }
        }
    }
    return $false
}

function Get-LocalContext {
    $ctx = @{ ips = @(); gateway = @(); dns = @() }
    try {
        $cfgs = @(Get-NetIPConfiguration -ErrorAction Stop)
        foreach ($c in $cfgs) {
            if ($c.IPv4Address) { foreach ($a in @($c.IPv4Address)) { $ctx.ips += [string]$a.IPAddress } }
            if ($c.IPv4DefaultGateway) { foreach ($g in @($c.IPv4DefaultGateway)) { $ctx.gateway += [string]$g.NextHop } }
            if ($c.DNSServer) {
                foreach ($d in @($c.DNSServer)) {
                    foreach ($s in @($d.ServerAddresses)) { if ($s -match '^\d{1,3}(\.\d{1,3}){3}$') { $ctx.dns += [string]$s } }
                }
            }
        }
    } catch { }
    return $ctx
}

function Get-PortList {
    if (-not [string]::IsNullOrWhiteSpace($Ports)) {
        $list = New-Object System.Collections.Generic.List[int]
        foreach ($chunk in ($Ports -split '[,\s]+')) {
            if ($chunk -match '^(\d{1,5})-(\d{1,5})$') {
                $a = [int]$matches[1]; $b = [int]$matches[2]
                if ($a -lt 1) { $a = 1 }
                if ($b -gt 65535) { $b = 65535 }
                if ($b -ge $a) {
                    if (($b - $a) -gt 2048) { $b = $a + 2048 }
                    for ($p = $a; $p -le $b; $p++) { $list.Add($p) }
                }
            } elseif ($chunk -match '^\d{1,5}$') {
                $p = [int]$chunk
                if ($p -ge 1 -and $p -le 65535) { $list.Add($p) }
            }
        }
        return @($list | Select-Object -Unique)
    }
    $key = $Profile.ToLowerInvariant()
    if ($script:Profiles.ContainsKey($key)) { return $script:Profiles[$key] }
    return $script:Profiles['common']
}

function Get-ServiceName {
    param([int]$Port)
    if ($script:ServiceNames.ContainsKey($Port)) { return $script:ServiceNames[$Port] }
    return ''
}

function Get-PortSeverity {
    param([int]$Port)
    if ($Port -in @(23, 21, 5900, 445, 3389)) { return 'high' }
    if ($Port -in @(139, 135, 1433, 3306, 5432, 5985, 6379, 9200, 11211, 27017)) { return 'med' }
    return 'info'
}

function Expand-Targets {
    param([string]$Spec)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($item in ($Spec -split '[,\s]+')) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        if ($item -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$') {
            $prefix = [int]$matches[5]
            if ($prefix -lt 22) {
                Write-Evt 'log' 'warn' ("Refused {0}: sweeps are capped at /22 to avoid flooding a network." -f $item)
                continue
            }
            $base = ((ConvertTo-IPLong ($matches[1] + '.' + $matches[2] + '.' + $matches[3] + '.' + $matches[4])))
            $size = [uint32][Math]::Pow(2, (32 - $prefix))
            $mask = [uint32]([uint32]::MaxValue -shl (32 - $prefix))
            $net = $base -band $mask
            $first = $net; $last = $net + $size - 1
            if ($prefix -le 30) { $first = $first + 1; $last = $last - 1 }
            $v = $first
            while ($v -le $last -and $list.Count -lt $script:MaxHosts) {
                $list.Add((ConvertFrom-IPLong $v)); $v++
            }
            continue
        }
        if ($item -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})$') {
            $a = [int]$matches[5]
            for ($i = $a; $i -le 254 -and $list.Count -lt $script:MaxHosts; $i++) {
                $list.Add(($matches[1] + '.' + $matches[2] + '.' + $matches[3] + '.' + $i))
            }
            continue
        }
        if ($item -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$') {
            $start = ConvertTo-IPLong ($matches[1] + '.' + $matches[2] + '.' + $matches[3] + '.' + $matches[4])
            $end = ConvertTo-IPLong $matches[5]
            if ($end -ge $start) {
                $v = $start
                while ($v -le $end -and $list.Count -lt $script:MaxHosts) { $list.Add((ConvertFrom-IPLong $v)); $v++ }
            }
            continue
        }
        if ($item -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $list.Add($item); continue
        }
        try {
            $addrs = @([Net.Dns]::GetHostAddresses($item) | Where-Object { $_.AddressFamily -eq 'InterNetwork' })
            foreach ($a in $addrs) { if ($list.Count -lt $script:MaxHosts) { $list.Add([string]$a.IPAddressToString) } }
        } catch {
            Write-Evt 'log' 'warn' ("Could not resolve: {0}" -f $item)
        }
    }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($ip in $list) { if (-not $out.Contains($ip)) { $out.Add($ip) } }
    return @($out)
}

function Resolve-IpName {
    param([string]$Ip)
    try {
        $t = [Net.Dns]::GetHostEntryAsync($Ip)
        if ($t.Wait(400)) { return [string]$t.Result.HostName } else { return '' }
    } catch { return '' }
}

function Get-ArpTable {
    $map = @{}
    try {
        foreach ($n in @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop)) {
            if ($n.State -ne 'Incomplete' -and $n.LinkLayerAddress -and $n.LinkLayerAddress -ne '00-00-00-00-00-00') {
                $map[[string]$n.IPAddress] = [string]$n.LinkLayerAddress
            }
        }
    } catch { }
    return $map
}

function Invoke-Sweep {
    param([string[]]$Ips)
    $alive = @()
    $tasks = @()
    foreach ($ip in $Ips) {
        try {
            $p = New-Object System.Net.NetworkInformation.Ping
            $tasks += [pscustomobject]@{ Ip = $ip; Ping = $p; Task = $p.SendPingAsync($ip, [Math]::Max(400, $TimeoutMs + 300)) }
        } catch { }
    }
    $done = 0
    foreach ($t in $tasks) {
        $isAlive = $false; $rtt = $null
        try {
            if ($t.Task.Wait([Math]::Max(800, $TimeoutMs + 600))) {
                $rep = $t.Task.Result
                if ($rep.Status -eq 'Success') { $isAlive = $true; $rtt = [int]$rep.RoundtripTime }
            }
        } catch { }
        $done++
        if ($isAlive) {
            Write-Evt 'host' 'info' $t.Ip @{ ip = $t.Ip; rtt = $rtt; src = 'icmp' }
            $alive += [pscustomobject]@{ Ip = $t.Ip; Rtt = $rtt }
        }
        if ($done % 8 -eq 0) { Write-Evt 'stat' 'info' '' @{ phase = 'sweep'; done = $done; total = $tasks.Count } }
    }
    Write-Evt 'stat' 'info' '' @{ phase = 'sweep'; done = $tasks.Count; total = $tasks.Count }
    return $alive
}

function Get-Banner {
    param([string]$Ip, [int]$Port)
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $task = $client.ConnectAsync($Ip, $Port)
        if (-not $task.Wait([Math]::Max(400, $TimeoutMs))) { return '' }
        if (-not $client.Connected) { return '' }
        $client.ReceiveTimeout = 500
        $stream = $client.GetStream()
        if ($Port -in @(80, 8080, 8000, 8081, 8888, 3000, 5000, 9000, 9200)) {
            $probe = "HEAD / HTTP/1.0`r`nHost: $Ip`r`nUser-Agent: NetTruder/1.0`r`n`r`n"
            $bytes = [Text.Encoding]::ASCII.GetBytes($probe)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        }
        Start-Sleep -Milliseconds 140
        if (-not $stream.DataAvailable) { return '' }
        $buf = New-Object byte[] 320
        $n = $stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return '' }
        $text = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
        $text = ($text -replace '[^\x20-\x7E]', ' ').Trim()
        if ($text.Length -gt 90) { $text = $text.Substring(0, 90) }
        return $text
    } catch { return '' }
    finally { if ($client) { try { $client.Close() } catch { } } }
}

function Invoke-PortScan {
    param([string]$Ip, [int[]]$PortList)
    $open = @()
    $batch = 24
    for ($i = 0; $i -lt $PortList.Count; $i += $batch) {
        if (Test-Path -LiteralPath $script:Stop) { break }
        $last = [Math]::Min($i + $batch - 1, $PortList.Count - 1)
        $slice = @($PortList[$i..$last])
        $workers = @()
        foreach ($p in $slice) {
            $c = New-Object System.Net.Sockets.TcpClient
            try { $c.NoDelay = $true } catch { }
            try {
                $t = $c.ConnectAsync($Ip, $p)
                $workers += [pscustomobject]@{ Port = $p; Client = $c; Task = $t }
            } catch { try { $c.Close() } catch { } }
        }
        foreach ($w in $workers) {
            $isOpen = $false
            try {
                if ($w.Task.Wait([Math]::Max(200, $TimeoutMs))) { $isOpen = [bool]$w.Client.Connected }
            } catch { $isOpen = $false }
            if ($isOpen) {
                $svc = Get-ServiceName $w.Port
                $sev = Get-PortSeverity $w.Port
                $banner = ''
                try { $w.Client.Close() } catch { }
                $banner = Get-Banner -Ip $Ip -Port $w.Port
                $open += [pscustomobject]@{ Port = $w.Port; Service = $svc; Severity = $sev }
                Write-Evt 'port' 'info' ("{0}:{1} open {2}" -f $Ip, $w.Port, $svc) @{ ip = $Ip; port = $w.Port; svc = $svc; sev = $sev; banner = $banner }
            }
            try { $w.Client.Close() } catch { }
        }
    }
    return $open
}

function Get-ProcName {
    param([int]$ProcId, $Cache)
    if ($ProcId -le 0) { return 'System' }
    if ($null -ne $Cache -and $Cache.ContainsKey($ProcId)) { return $Cache[$ProcId] }
    $name = ('pid{0}' -f $ProcId)
    try { $name = (Get-Process -Id $ProcId -ErrorAction Stop).ProcessName } catch { }
    if ($null -ne $Cache) { $Cache[$ProcId] = $name }
    return $name
}

function Get-AlertRemedy {
    param(
        [string]$Id,
        [string]$Proc = '',
        [string]$Ip = '',
        [string]$Ports = '',
        [string[]]$Hosts = @()
    )
    $steps = @()
    $native = 'taskmgr.exe'
    $title = 'Triage the alert'
    switch -Wildcard ($Id) {
        'LATERAL_FANOUT' {
            $title = 'Possible lateral movement or worm-like spread'
            $steps = @(
                'Treat this as possible lateral movement until the process is identified. Collect the peer addresses and ports from the alert.',
                'Check Security 5140/5145 share access, 4624 type 3 logons and System 7045 service installs on the named peers.',
                'Confirm whether the process is an approved management tool. A browser or update service does not normally touch 445, 135 or 3389 across peers.',
                'If it is not approved, contain the host at the switch or host firewall and preserve the process tree and command line.',
                'Review local Administrator rights and block client-to-client SMB/RDP. NetTruder never weakens a control.'
            )
            $native = 'wf.msc'
        }
        'FANOUT' {
            $title = 'Process contacted many hosts quickly'
            $steps = @(
                'Identify the owning process and its parent in the Processes view or Task Manager.',
                'If the process is a browser, verify the destinations are browser CDN or telemetry endpoints before escalating. Browser fan-out is common and is scored lower for that reason.',
                'If it is not a browser, treat the host as a possible scanner or worm and check peer logs for 5140/5145, 4624 type 3 and 7045.',
                'Capture the destination list and command line, then decide whether the host should be isolated.',
                'Keep the FANOUT and LATERAL_FANOUT rules armed; tune a documented exception rather than disabling the IDS.'
            )
            $native = 'taskmgr.exe'
        }
        'BEACON_CADENCE' {
            $title = 'Repeating connection cadence'
            $steps = @(
                'Identify the process that owns the repeating sessions and the destination.',
                'Confirm whether the destination and cadence are expected for an approved application.',
                'Collect a packet capture or firewall log if policy allows, and compare the cadence across reboots.',
                'Do not disable the IDS. If the traffic is sanctioned, create a documented, scoped exception.'
            )
            $native = 'resmon.exe'
        }
        'EGRESS_*' {
            $title = 'Admin tool egress'
            $steps = @(
                'Capture the command line and destination from the alert detail.',
                'Inspect the process tree and check the endpoint product log before calling this an IDS miss or a block.',
                'A signed system host used outside its normal role is proxy execution. Treat the parent image and arguments as the signal.',
                'Block the destination at the firewall only with authorisation, and keep the endpoint control in place.'
            )
            $native = 'wf.msc'
        }
        'LISTEN_*' {
            $title = 'Exposed service listener'
            $steps = @(
                'Identify the service and owning process for the listening port.',
                'Confirm whether the listener is required on this host and whether it is reachable from untrusted networks.',
                'Restrict the port with the host firewall to management hosts, or move the service behind a jump host.',
                'Patch or reconfigure the service through its own product settings. Do not disable a security control.'
            )
            $native = 'wf.msc'
        }
        'REMOTE_*' {
            $title = 'Outbound session to a flagged port'
            $steps = @(
                'Identify the process and destination for the outbound session.',
                'Confirm whether the port is expected for this host and application.',
                'If the port is a known handler or backdoor port, isolate the host and collect the process tree.',
                'Preserve evidence before terminating anything, then remove the cause rather than the alert.'
            )
            $native = 'resmon.exe'
        }
        default {
            $steps = @(
                'Review the process, destination and command line in the alert.',
                'Use Task Manager, Resource Monitor and the firewall console to confirm the owner.',
                'Preserve evidence before changing the host. NetTruder never weakens a control.'
            )
        }
    }
    return [pscustomobject]@{
        title = $title
        steps = @($steps)
        native = $native
        note = 'NetTruder offers enable, harden, inspect, copy and native-UI actions. It never offers to turn a security control off.'
    }
}

function New-Alert {
    param(
        [string]$Id, [string]$Sev, [string]$Title, [string]$Detail,
        [string]$Ip = '', [string]$Proc = '', [int]$ProcId = 0, [int]$CooldownSec = 300,
        [string[]]$Hosts = @(), [string]$Ports = '', $Remedy = $null
    )
    $key = "$Id|$Ip|$Proc"
    $now = Get-Date
    if ($script:Cooldown.ContainsKey($key)) {
        if (($now - $script:Cooldown[$key]).TotalSeconds -lt $CooldownSec) { return }
    }
    $script:Cooldown[$key] = $now
    if ($null -eq $Remedy) {
        $Remedy = Get-AlertRemedy -Id $Id -Proc $Proc -Ip $Ip -Ports $Ports -Hosts $Hosts
    }
    Write-Evt 'alert' 'warn' $Title @{
        id = $Id; sev = $Sev; title = $Title; detail = $Detail
        ip = $Ip; proc = $Proc; pid = $ProcId
        hosts = @($Hosts); ports = $Ports; remedy = $Remedy
    }
    Write-Audit 'alert' $Title @{
        id = $Id; sev = $Sev; ip = $Ip; proc = $Proc; pid = $ProcId
        detail = $Detail; hosts = @($Hosts); ports = $Ports
    }
    if ($AutoBlock -and $Sev -eq 'high' -and -not [string]::IsNullOrWhiteSpace($Ip) -and -not (Test-PrivateIp $Ip)) {
        Invoke-Block -Ip $Ip -Minutes $DurationMin -Reason ('auto:' + $Id) -Silent
    }
}

function Invoke-Watch {
    $rules = Get-Rules
    $listenMap = @{}
    foreach ($r in @($rules.listenPorts)) { if ($r) { $listenMap[[int]$r.port] = $r } }
    $remoteMap = @{}
    foreach ($r in @($rules.remotePorts)) { if ($r) { $remoteMap[[int]$r.port] = $r } }
    $egressMap = @{}
    foreach ($r in @($rules.egressWatch)) {
        if (-not $r -or -not $r.process) { continue }
        $pk = ([string]$r.process).ToLowerInvariant()
        if ($pk.EndsWith('.exe')) { $pk = $pk.Substring(0, $pk.Length - 4) }
        $egressMap[$pk] = $r
    }

    $beacon = $rules.beacon
    $fanout = $rules.fanout
    $browserProcs = @()
    foreach ($bp in @($fanout.browserProcs)) {
        $b = ([string]$bp).ToLowerInvariant()
        if ($b.EndsWith('.exe')) { $b = $b.Substring(0, $b.Length - 4) }
        if ($b) { $browserProcs += $b }
    }
    $lateralPorts = @()
    foreach ($lp in @(([string]$fanout.lateralPorts) -split ',')) {
        $n = 0
        if ([int]::TryParse($lp.Trim(), [ref]$n)) { $lateralPorts += $n }
    }
    if ($lateralPorts.Count -eq 0) { $lateralPorts = @(135, 139, 445, 3389, 5985, 5986, 22) }
    Write-Evt 'log' 'ok' ("IDS online - poll {0}s - {1} listener rules - {2} remote-port rules - {3} admin-tool egress rules - ruleset {4}" -f $IntervalSec, $listenMap.Count, $remoteMap.Count, $egressMap.Count, $rules.version)
    Write-Audit 'watch' 'IDS monitor started' @{ ruleset = $rules.version; egressRules = $egressMap.Count }

    $pidFile = Join-Path $script:Runs ("{0}.pid" -f $RunId)
    try { [IO.File]::WriteAllText($pidFile, "$PID") } catch { }

    $seen = @{}
    $remoteTimes = @{}
    $procFan = @{}
    $procPorts = @{}
    $pname = @{}
    $started = Get-Date

    try {
        while ($true) {
            if (Test-Path -LiteralPath $script:Stop) { break }
            if (((Get-Date) - $started).TotalSeconds -gt 86400) { break }

            $conns = @()
            try { $conns = @(Get-NetTCPConnection -ErrorAction Stop) } catch {
                Write-Evt 'log' 'warn' 'Connection table unavailable this cycle; retrying.'
                Start-Sleep -Seconds $IntervalSec
                continue
            }

            $now = Get-Date
            foreach ($c in $conns) {
                $state = [string]$c.State
                $lp = [int]$c.LocalPort
                $rp = [int]$c.RemotePort
                $ra = [string]$c.RemoteAddress
                $opid = [int]$c.OwningProcess

                if ($state -eq 'Listen') {
                    $key = ('L|{0}|{1}' -f $lp, $opid)
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $now
                    if ($listenMap.ContainsKey($lp)) {
                        $r = $listenMap[$lp]
                        New-Alert -Id ('LISTEN_' + $lp) -Sev ([string]$r.sev) -Title ("Exposed service: {0} listening on {1}" -f $r.service, $lp) -Detail ([string]$r.why) -Proc (Get-ProcName $opid $pname) -ProcId $opid
                    }
                    continue
                }
                if ($state -ne 'Established') { continue }
                if ($ra -in @('127.0.0.1', '0.0.0.0', '::', '::1', '')) { continue }
                if ($opid -eq $PID) { continue }

                $key = ('E|{0}|{1}|{2}' -f $ra, $rp, $opid)
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $now
                $pn = Get-ProcName $opid $pname

                if ($remoteMap.ContainsKey($rp)) {
                    $r = $remoteMap[$rp]
                    New-Alert -Id ('REMOTE_' + $rp) -Sev ([string]$r.sev) -Title ("Outbound session to flagged port {0} ({1})" -f $rp, $pn) -Detail ([string]$r.why) -Ip $ra -Proc $pn -ProcId $opid
                }

                # --- admin-tool egress: certutil, bitsadmin and the proxy-execution hosts ---
                $pnl = $pn.ToLowerInvariant()
                if ($egressMap.ContainsKey($pnl)) {
                    $er = $egressMap[$pnl]
                    if (Test-PortInSpec -Port $rp -Spec ([string]$er.ports)) {
                        $cmdline = ''
                        try {
                            $cim = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $opid) -ErrorAction Stop
                            if ($cim) { $cmdline = [string]$cim.CommandLine }
                        } catch { }
                        $detail = [string]$er.why
                        if ($cmdline) { $detail = $detail + ' Command line: ' + $cmdline }
                        else { $detail = $detail + ' Command line not readable for this process; enable 4688 command-line auditing.' }
                        New-Alert -Id ('EGRESS_' + $pnl.ToUpperInvariant()) -Sev ([string]$er.sev) -Title ("Admin tool egress: {0} -> {1}:{2}" -f $pn, $ra, $rp) -Detail $detail -Ip $ra -Proc $pn -ProcId $opid -CooldownSec 600
                    }
                }

                if (-not $remoteTimes.ContainsKey($ra)) { $remoteTimes[$ra] = New-Object System.Collections.ArrayList }
                [void]$remoteTimes[$ra].Add($now)

                if (-not $procFan.ContainsKey($pn)) { $procFan[$pn] = @{} }
                $procFan[$pn][$ra] = $now
                if (-not $procPorts.ContainsKey($pn)) { $procPorts[$pn] = @{} }
                if (-not $procPorts[$pn].ContainsKey($ra)) { $procPorts[$pn][$ra] = @{} }
                $procPorts[$pn][$ra][$rp] = $true
            }

            # --- beaconing heuristic: repeated connections at a steady cadence ---
            $win = [int]$beacon.windowSec
            foreach ($ip in @($remoteTimes.Keys)) {
                $arr = $remoteTimes[$ip]
                $kept = New-Object System.Collections.ArrayList
                foreach ($ts in $arr) { if (($now - $ts).TotalSeconds -le $win) { [void]$kept.Add($ts) } }
                $remoteTimes[$ip] = $kept
                if ($kept.Count -lt [int]$beacon.minConnections) { continue }
                $vals = @($kept | Sort-Object)
                $gaps = @()
                for ($g = 1; $g -lt $vals.Count; $g++) { $gaps += ($vals[$g] - $vals[$g - 1]).TotalSeconds }
                if ($gaps.Count -lt 3) { continue }
                $mean = ($gaps | Measure-Object -Average).Average
                if ($mean -lt [double]$beacon.minMeanSec -or $mean -gt [double]$beacon.maxMeanSec) { continue }
                $var = 0.0
                foreach ($v in $gaps) { $var += [Math]::Pow(($v - $mean), 2) }
                $var = $var / $gaps.Count
                $sd = [Math]::Sqrt($var)
                $jitter = $sd / $mean
                if ($jitter -le [double]$beacon.maxJitter) {
                    New-Alert -Id 'BEACON_CADENCE' -Sev ([string]$beacon.sev) -Title ("Repeating connection cadence to {0}" -f $ip) -Detail ("{0} new sessions in {1}s, mean interval {2:N0}s, jitter {3:P0}. Steady cadence is a common C2 beacon trait; confirm the owning process." -f $kept.Count, $win, $mean, $jitter) -Ip $ip -CooldownSec 900
                }
            }

            # --- fanout heuristic: one process touching many hosts quickly ---
            # Two outcomes are separated. Sensitive-port fan-out on 135/139/445/
            # 3389/5985/5986/22 is a lateral-movement shape and stays high.
            # Browser fan-out to CDN and telemetry endpoints is common, so it is
            # reported at a lower severity instead of being suppressed.
            foreach ($pn in @($procFan.Keys)) {
                $map = $procFan[$pn]
                $fresh = @{}
                foreach ($ip in @($map.Keys)) {
                    if (($now - $map[$ip]).TotalSeconds -le [int]$fanout.windowSec) { $fresh[$ip] = $map[$ip] }
                }
                $procFan[$pn] = $fresh
                if ($procPorts.ContainsKey($pn)) {
                    foreach ($ip in @($procPorts[$pn].Keys)) {
                        if (-not $fresh.ContainsKey($ip)) { [void]$procPorts[$pn].Remove($ip) }
                    }
                }

                $pnl = $pn.ToLowerInvariant()
                $lateralHosts = @()
                $lateralSeen = @{}
                $anyPorts = @{}
                if ($procPorts.ContainsKey($pn)) {
                    foreach ($ip in @($fresh.Keys)) {
                        if (-not $procPorts[$pn].ContainsKey($ip)) { continue }
                        foreach ($port in @($procPorts[$pn][$ip].Keys)) {
                            $pi = [int]$port
                            $anyPorts[$pi] = $true
                            if ($lateralPorts -contains $pi) {
                                if ($lateralHosts -notcontains $ip) { $lateralHosts += $ip }
                                $lateralSeen[$pi] = $true
                            }
                        }
                    }
                }
                $portText = (($anyPorts.Keys | Sort-Object) -join ',')

                if ($lateralHosts.Count -ge [int]$fanout.lateralHosts) {
                    $sample = @($lateralHosts | Sort-Object | Select-Object -First 12)
                    $latPorts = (($lateralSeen.Keys | Sort-Object) -join ',')
                    New-Alert -Id 'LATERAL_FANOUT' -Sev ([string]$fanout.lateralSev) `
                        -Title ("Sensitive-port fan-out from {0} to {1} peers" -f $pn, $lateralHosts.Count) `
                        -Detail ("One process opened sessions to {0} peers on sensitive ports ({1}) within {2}s. That is the network shape of SMB, RPC, WinRM or RDP spread, not browser fan-out. Peers: {3}." -f $lateralHosts.Count, $latPorts, $fanout.windowSec, ($sample -join ', ')) `
                        -Proc $pn -Hosts $sample -Ports $latPorts -CooldownSec 600
                } elseif ($fresh.Count -ge [int]$fanout.distinctHosts) {
                    $sample = @($fresh.Keys | Sort-Object | Select-Object -First 12)
                    $isBrowser = ($browserProcs -contains $pnl)
                    $sev = [string]$fanout.sev
                    $detail = ("One process opened sessions to {0} distinct hosts within {1}s. That pattern matches scanning or worm-like spread. Ports: {2}. Hosts: {3}." -f $fresh.Count, $fanout.windowSec, $(if ($portText) { $portText } else { 'n/a' }), ($sample -join ', '))
                    if ($isBrowser) {
                        $sev = [string]$fanout.browserSev
                        $detail = ("Browser fan-out: {0} opened sessions to {1} distinct hosts within {2}s. Browsers commonly contact CDN, update and telemetry endpoints in parallel, so this is scored lower. Confirm the destinations and parent process before escalating. Ports: {3}. Hosts: {4}." -f $pn, $fresh.Count, $fanout.windowSec, $(if ($portText) { $portText } else { 'n/a' }), ($sample -join ', '))
                    }
                    New-Alert -Id 'FANOUT' -Sev $sev -Title ("Fan-out from {0} to {1} hosts" -f $pn, $fresh.Count) -Detail $detail -Proc $pn -Hosts $sample -Ports $portText -CooldownSec 600
                }
            }

            # --- bound memory ---
            if ($seen.Count -gt 4000) {
                $cut = @{}
                foreach ($k in @($seen.Keys)) { if (($now - $seen[$k]).TotalMinutes -le 10) { $cut[$k] = $seen[$k] } }
                $seen = $cut
            }
            if ($remoteTimes.Count -gt 800) { $remoteTimes = @{} }

            Start-Sleep -Seconds ([Math]::Max(1, $IntervalSec))
        }
    } finally {
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        Write-Evt 'log' 'ok' 'IDS monitor disarmed.'
        Write-Evt 'done' 'ok' 'Monitor stopped.' @{ phase = 'watch' }
        Write-Audit 'watch' 'IDS monitor stopped'
    }
}

function Invoke-Block {
    param([string]$Ip, [int]$Minutes = 10, [string]$Reason = 'manual', [switch]$Silent)
    if (-not (Test-Admin)) {
        Write-Evt 'log' 'err' 'IPS needs an elevated session. Relaunch with Launch-Elevated.cmd or as Administrator.'
        return
    }
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Ip, [ref]$parsed)) {
        Write-Evt 'log' 'err' ("Not a valid IPv4 address: {0}" -f $Ip)
        return
    }
    if ($parsed.AddressFamily -ne 'InterNetwork') {
        Write-Evt 'log' 'err' 'Only IPv4 targets can be blocked.'
        return
    }
    if ($Ip -match '^(0\.|127\.|224\.|225\.|226\.|227\.|228\.|229\.|230\.|231\.|232\.|233\.|234\.|235\.|236\.|237\.|238\.|239\.|255\.)') {
        Write-Evt 'log' 'err' ("Refused reserved or loopback address: {0}" -f $Ip)
        return
    }

    $ctx = Get-LocalContext
    if ($ctx.ips -contains $Ip) { Write-Evt 'log' 'err' 'Refused: that address is this machine.'; return }
    if ($ctx.gateway -contains $Ip) { Write-Evt 'log' 'err' 'Refused: that address is the default gateway. Blocking it drops the network.'; return }
    if ($ctx.dns -contains $Ip) { Write-Evt 'log' 'err' 'Refused: that address is a configured DNS server.'; return }
    if ((Test-PrivateIp $Ip) -and -not $Yes) {
        Write-Evt 'log' 'err' ("Refused: {0} is on a private range. Blocking a LAN peer can disrupt shared devices; confirm explicitly to proceed." -f $Ip)
        return
    }

    $journal = @(Get-Journal)
    $existing = @($journal | Where-Object { $_.ip -eq $Ip })
    if ($existing.Count -gt 0) {
        Write-Evt 'log' 'warn' ("Already blocked: {0}" -f $Ip)
        return
    }
    if ($journal.Count -ge 30) {
        Write-Evt 'log' 'err' 'Refused: 30 active NetTruder blocks already. Release some first.'
        return
    }

    if ($Minutes -lt 1) { $Minutes = 1 }
    if ($Minutes -gt 240) { $Minutes = 240 }
    $names = @("NetTruder-IPS-$Ip-in", "NetTruder-IPS-$Ip-out")
    $expires = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + ($Minutes * 60)
    try {
        foreach ($n in $names) { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue }
        New-NetFirewallRule -DisplayName $names[0] -Direction Inbound -Action Block -RemoteAddress $Ip -Profile Any -Description ("NetTruder IPS: {0}. Expires automatically." -f $Reason) | Out-Null
        New-NetFirewallRule -DisplayName $names[1] -Direction Outbound -Action Block -RemoteAddress $Ip -Profile Any -Description ("NetTruder IPS: {0}. Expires automatically." -f $Reason) | Out-Null
    } catch {
        Write-Evt 'log' 'err' ("Firewall rule creation failed: {0}" -f $_.Exception.Message)
        return
    }
    $journal += [pscustomobject]@{ ip = $Ip; names = $names; createdEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); expiresEpoch = $expires; reason = $Reason }
    Save-Journal $journal
    Write-Audit 'block' ("Blocked {0} for {1} minutes ({2})" -f $Ip, $Minutes, $Reason) @{ ip = $Ip; minutes = $Minutes; reason = $Reason }
    Write-Evt 'log' 'ok' ("IPS blocked {0} for {1} min ({2})" -f $Ip, $Minutes, $Reason)
    Write-Evt 'blocklist' 'info' '' @{ items = @(Get-Journal) }
}

function Invoke-Unblock {
    param([string]$Ip)
    if (-not (Test-Admin)) { Write-Evt 'log' 'err' 'IPS needs an elevated session.'; return }
    $journal = @(Get-Journal)
    $keep = @(); $hit = $null
    foreach ($it in $journal) {
        if ($it.ip -eq $Ip) { $hit = $it } else { $keep += $it }
    }
    if ($null -eq $hit) { Write-Evt 'log' 'warn' ("No NetTruder block recorded for {0}" -f $Ip); return }
    foreach ($n in @($hit.names)) { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue }
    Save-Journal $keep
    Write-Audit 'unblock' ("Released {0}" -f $Ip) @{ ip = $Ip }
    Write-Evt 'log' 'ok' ("Released {0}" -f $Ip)
    Write-Evt 'blocklist' 'info' '' @{ items = @(Get-Journal) }
}

function Invoke-Release {
    if (-not (Test-Admin)) { Write-Evt 'log' 'err' 'IPS needs an elevated session.'; return }
    $journal = @(Get-Journal)
    foreach ($it in $journal) { foreach ($n in @($it.names)) { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue } }
    Remove-NetFirewallRule -DisplayName 'NetTruder-IPS-*' -ErrorAction SilentlyContinue
    Save-Journal @()
    Write-Audit 'release' 'Released all NetTruder IPS rules'
    Write-Evt 'log' 'ok' 'All NetTruder IPS rules released.'
    Write-Evt 'blocklist' 'info' '' @{ items = @() }
}

function Invoke-Expire {
    param([switch]$Quiet)
    $journal = @(Get-Journal)
    if ($journal.Count -eq 0) { return }
    if (-not (Test-Admin)) { return }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $keep = @(); $removed = 0
    foreach ($it in $journal) {
        if ([long]$it.expiresEpoch -lt $now) {
            foreach ($n in @($it.names)) { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue }
            $removed++
            if (-not $Quiet) { Write-Evt 'log' 'ok' ("Expired block released: {0}" -f $it.ip) }
        } else { $keep += $it }
    }
    if ($removed -gt 0) {
        Save-Journal $keep
        Write-Audit 'expire' ("Released {0} expired rule(s)" -f $removed)
        if (-not $Quiet) { Write-Evt 'blocklist' 'info' '' @{ items = @(Get-Journal) } }
    }
}

function Invoke-Probe {
    Write-Audit 'probe' 'Posture probe'
    $rules = Get-Rules
    $listenMap = @{}
    foreach ($r in @($rules.listenPorts)) { if ($r) { $listenMap[[int]$r.port] = $r } }

    # Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $rt = [bool]$mp.RealTimeProtectionEnabled
        Write-Evt 'posture' 'info' 'Microsoft Defender real-time protection' @{
            id = 'defender-rt'; state = $(if ($rt) { 'on' } else { 'off' }); sev = $(if ($rt) { 'ok' } else { 'high' })
            detail = $(if ($rt) { 'Real-time protection is enabled.' } else { 'Real-time protection is OFF. This is the single highest-impact gap.' })
        }
        $age = [int]$mp.AntivirusSignatureAge
        Write-Evt 'posture' 'info' 'Antivirus signatures' @{
            id = 'defender-sig'; state = ("{0} day(s)" -f $age); sev = $(if ($age -le 3) { 'ok' } elseif ($age -le 10) { 'med' } else { 'high' })
            detail = $(if ($age -le 3) { 'Signatures are current.' } else { 'Signatures are aging; let Defender update.' })
        }
    } catch {
        Write-Evt 'posture' 'info' 'Microsoft Defender status' @{ id = 'defender'; state = 'unknown'; sev = 'info'; detail = 'Defender cmdlets unavailable on this system.' }
    }

    # Firewall
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $off = @($profiles | Where-Object { -not $_.Enabled })
        Write-Evt 'posture' 'info' 'Windows Firewall' @{
            id = 'firewall'; state = $(if ($off.Count -eq 0) { 'all profiles on' } else { 'profile off' })
            sev = $(if ($off.Count -eq 0) { 'ok' } else { 'high' })
            detail = $(if ($off.Count -eq 0) { 'Domain, private and public profiles are enabled.' } else { ('Disabled profile(s): ' + (($off | ForEach-Object { $_.Name }) -join ', ')) })
        }
    } catch { }

    # SMBv1
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        $s1 = [bool]$smb.EnableSMB1Protocol
        Write-Evt 'posture' 'info' 'SMBv1 protocol' @{
            id = 'smbv1'; state = $(if ($s1) { 'enabled' } else { 'disabled' }); sev = $(if ($s1) { 'high' } else { 'ok' })
            detail = $(if ($s1) { 'SMBv1 is enabled. It is obsolete and exploited by ransomware worms.' } else { 'SMBv1 is disabled.' })
        }
    } catch { }

    # RDP
    try {
        $rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
        $on = ([int]$rdp.fDenyTSConnections -eq 0)
        Write-Evt 'posture' 'info' 'Remote Desktop' @{
            id = 'rdp'; state = $(if ($on) { 'listening' } else { 'disabled' }); sev = $(if ($on) { 'med' } else { 'ok' })
            detail = $(if ($on) { 'RDP is enabled. Require NLA, strong accounts and MFA, and never expose it directly.' } else { 'Inbound RDP is disabled.' })
        }
    } catch { }

    # BitLocker
    try {
        $vol = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -eq 'OperatingSystem' })
        if ($vol.Count -gt 0) {
            $st = [string]$vol[0].ProtectionStatus
            Write-Evt 'posture' 'info' 'OS volume encryption' @{
                id = 'bitlocker'; state = $st.ToLowerInvariant(); sev = $(if ($st -eq 'On') { 'ok' } else { 'med' })
                detail = $(if ($st -eq 'On') { 'The OS volume is protected by BitLocker.' } else { 'The OS volume is not protected. Theft of the device exposes data at rest.' })
            }
        }
    } catch { }

    # Update service
    try {
        $wu = Get-Service -Name wuauserv -ErrorAction Stop
        Write-Evt 'posture' 'info' 'Windows Update service' @{
            id = 'wuauserv'; state = [string]$wu.Status
            sev = $(if ($wu.Status -eq 'Running') { 'ok' } else { 'info' })
            detail = 'Read-only check. Updates are never modified by NetTruder.'
        }
    } catch { }

    # Exposed high-risk listeners
    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $hits = @()
        foreach ($l in $listeners) {
            if ($listenMap.ContainsKey([int]$l.LocalPort)) {
                $addr = [string]$l.LocalAddress
                if ($addr -eq '0.0.0.0' -or $addr -eq '::') {
                    $hits += ('{0}/{1}' -f $l.LocalPort, $listenMap[[int]$l.LocalPort].service)
                }
            }
        }
        Write-Evt 'posture' 'info' 'High-risk services bound to all interfaces' @{
            id = 'exposed-listeners'; state = $(if ($hits.Count -eq 0) { 'none' } else { "$($hits.Count) found" })
            sev = $(if ($hits.Count -eq 0) { 'ok' } else { 'high' })
            detail = $(if ($hits.Count -eq 0) { 'No high-risk service is listening on every interface.' } else { ($hits -join ', ') })
        }
    } catch { }

    # Existing IPS state
    $journal = @(Get-Journal)
    Write-Evt 'posture' 'info' 'NetTruder IPS rules' @{
        id = 'ips'; state = ("{0} active" -f $journal.Count); sev = 'info'
        detail = $(if ($journal.Count -eq 0) { 'No host blocks are active.' } else { (($journal | ForEach-Object { $_.ip }) -join ', ') })
    }

    Write-Evt 'blocklist' 'info' '' @{ items = $journal }
    Write-Evt 'done' 'ok' 'Posture probe complete.' @{ phase = 'probe' }
    Write-Evt 'log' 'ok' 'Posture probe complete - read-only checks only.'
}

function Invoke-Shell {
    param([string]$Command, [string]$Dir, [int]$MaxSec)
    if ([string]::IsNullOrWhiteSpace($Command)) {
        Write-Evt 'log' 'err' 'Empty command.'
        Write-Evt 'done' 'err' 'No command.' @{ phase = 'shell' }
        return
    }
    $cwd = $Dir
    if ([string]::IsNullOrWhiteSpace($cwd) -or -not (Test-Path -LiteralPath $cwd)) { $cwd = $env:USERPROFILE }
    $outFile = Join-Path $script:Runs ("{0}.out.txt" -f $RunId)
    $errFile = Join-Path $script:Runs ("{0}.err.txt" -f $RunId)
    foreach ($f in @($outFile, $errFile)) { try { [IO.File]::WriteAllText($f, '') } catch { } }

    Write-Evt 'log' 'dim' ("exec: {0}" -f $Command)
    Write-Audit 'shell' $Command @{ dir = $cwd }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/d /s /c "chcp 65001>nul & (' + $Command + ') > "' + $outFile + '" 2> "' + $errFile + '"'
    $psi.WorkingDirectory = $cwd
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = 'Hidden'

    $proc = $null
    try { $proc = [Diagnostics.Process]::Start($psi) } catch {
        Write-Evt 'term' 'err' ("Could not start shell: {0}" -f $_.Exception.Message) @{ s = 'err' }
        Write-Evt 'done' 'err' 'Shell failed.' @{ phase = 'shell' }
        return
    }

    $oOff = 0; $oBuf = ''; $eOff = 0; $eBuf = ''
    $deadline = (Get-Date).AddSeconds([Math]::Max(5, $MaxSec))
    $killed = $false

    function Read-Delta {
        param([string]$Path, [ref]$Offset, [ref]$Buffer)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        $lines = New-Object System.Collections.Generic.List[string]
        $fs = $null
        try {
            $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            if ($fs.Length -le $Offset.Value) { return @() }
            [void]$fs.Seek($Offset.Value, [IO.SeekOrigin]::Begin)
            $len = [int]($fs.Length - $Offset.Value)
            $bytes = New-Object byte[] $len
            $read = $fs.Read($bytes, 0, $len)
            $Offset.Value = $Offset.Value + $read
            $text = $Buffer.Value + [Text.Encoding]::UTF8.GetString($bytes, 0, $read)
        } catch { return @() }
        finally { if ($fs) { $fs.Dispose() } }
        $parts = $text -split "`n"
        $Buffer.Value = $parts[$parts.Count - 1]
        for ($i = 0; $i -lt $parts.Count - 1; $i++) { $lines.Add($parts[$i].TrimEnd("`r")) }
        return @($lines)
    }

    while ($true) {
        foreach ($ln in (Read-Delta $outFile ([ref]$oOff) ([ref]$oBuf))) {
            Write-Evt 'term' 'out' $ln @{ s = 'out' }
        }
        foreach ($ln in (Read-Delta $errFile ([ref]$eOff) ([ref]$eBuf))) {
            Write-Evt 'term' 'err' $ln @{ s = 'err' }
        }
        if (Test-Path -LiteralPath $script:Stop) {
            & taskkill.exe /T /F /PID $proc.Id 2>$null | Out-Null
            $killed = $true
            Write-Evt 'log' 'warn' 'Command terminated by operator.'
            break
        }
        if ((Get-Date) -gt $deadline) {
            & taskkill.exe /T /F /PID $proc.Id 2>$null | Out-Null
            $killed = $true
            Write-Evt 'log' 'warn' ('Command exceeded {0}s and was terminated.' -f $MaxSec)
            break
        }
        if ($proc.HasExited) {
            Start-Sleep -Milliseconds 120
            foreach ($ln in (Read-Delta $outFile ([ref]$oOff) ([ref]$oBuf))) { Write-Evt 'term' 'out' $ln @{ s = 'out' } }
            foreach ($ln in (Read-Delta $errFile ([ref]$eOff) ([ref]$eBuf))) { Write-Evt 'term' 'err' $ln @{ s = 'err' } }
            break
        }
        Start-Sleep -Milliseconds 90
    }

    if ($oBuf.Length -gt 0) { Write-Evt 'term' 'out' $oBuf @{ s = 'out' }; $oBuf = '' }
    if ($eBuf.Length -gt 0) { Write-Evt 'term' 'err' $eBuf @{ s = 'err' }; $eBuf = '' }

    $code = -1
    try { if ($proc.HasExited) { $code = $proc.ExitCode } } catch { }
    if ($killed) { $code = -1 }
    Write-Evt 'termexit' 'info' ("exit {0}" -f $code) @{ code = $code }
    Write-Evt 'done' 'ok' 'Command finished.' @{ phase = 'shell' }
}

function Get-OwnerMap {
    param([int[]]$Ids)
    $map = @{}
    if ($null -eq $Ids -or $Ids.Count -eq 0) { return $map }

    # Fast token-based owner lookup. GetOwner via CIM costs ~250 ms per process.
    if (-not ('NetTruder.NativeOwner' -as [type])) {
        $code = @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace NetTruder {
  public static class NativeOwner {
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int len, out int ret);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static string Lookup(int pid) {
      IntPtr h = OpenProcess(0x0400, false, pid);
      if (h == IntPtr.Zero) { h = OpenProcess(0x1000, false, pid); }
      if (h == IntPtr.Zero) { return ""; }
      IntPtr tok;
      if (!OpenProcessToken(h, 0x0008, out tok)) { CloseHandle(h); return ""; }
      try {
        int len;
        GetTokenInformation(tok, 1, IntPtr.Zero, 0, out len);
        IntPtr buf = Marshal.AllocHGlobal(len);
        try {
          if (!GetTokenInformation(tok, 1, buf, len, out len)) { return ""; }
          SecurityIdentifier sid = new SecurityIdentifier(Marshal.ReadIntPtr(buf));
          try { return sid.Translate(typeof(NTAccount)).Value; } catch { return sid.Value; }
        } finally { Marshal.FreeHGlobal(buf); }
      } finally { CloseHandle(tok); CloseHandle(h); }
    }
  }
}
'@
        try { Add-Type -TypeDefinition $code -ErrorAction Stop } catch { return $map }
    }

    foreach ($id in $Ids) {
        try {
            $v = [NetTruder.NativeOwner]::Lookup([int]$id)
            if ($v) { $map[[int]$id] = [string]$v }
        } catch { }
    }
    return $map
}

function Invoke-Processes {
    param([int]$Limit = 90)

    Write-Audit 'processes' 'Process inventory'
    Write-Evt 'log' 'dim' 'Collecting process inventory (read-only).'

    # Owner PID for every listening socket, plus a connection count per process.
    $portsByPid = @{}
    $connsByPid = @{}
    try {
        foreach ($c in @(Get-NetTCPConnection -ErrorAction Stop)) {
            $op = [int]$c.OwningProcess
            if ($op -le 0) { continue }
            $connsByPid[$op] = 1 + [int]$connsByPid[$op]
            if ([string]$c.State -eq 'Listen') {
                if (-not $portsByPid.ContainsKey($op)) { $portsByPid[$op] = New-Object System.Collections.ArrayList }
                [void]$portsByPid[$op].Add([int]$c.LocalPort)
            }
        }
    } catch {
        Write-Evt 'log' 'warn' 'Connection table unavailable this pass; ports are omitted.'
    }

    # Two CPU samples 600 ms apart give a live percentage per process.
    $cores = [Math]::Max(1, [Environment]::ProcessorCount)
    $snap = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        try { $snap[[int]$p.Id] = [double]$p.CPU } catch { }
    }
    Start-Sleep -Milliseconds 600
    $span = 0.6

    $rows = @()
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $op = [int]$p.Id
        $cpu = 0.0
        if ($snap.ContainsKey($op)) {
            try { $cpu = ((([double]$p.CPU - [double]$snap[$op]) / $span) / $cores) * 100.0 } catch { }
        }
        if ($cpu -lt 0) { $cpu = 0 }
        $ws = 0
        try { $ws = [int64]$p.WorkingSet64 } catch { }
        $ports = @()
        if ($portsByPid.ContainsKey($op)) { $ports = @($portsByPid[$op] | Sort-Object -Unique) }
        $rows += [pscustomobject]@{
            pid = $op
            name = [string]$p.ProcessName
            cpu = [Math]::Round($cpu, 1)
            ws = $ws
            ports = $ports
            conns = [int]$connsByPid[$op]
        }
    }

    $rows = @($rows | Sort-Object `
        @{ Expression = { if ($_.ports.Count -gt 0) { 1 } else { 0 } }; Descending = $true }, `
        @{ Expression = { $_.cpu }; Descending = $true }, `
        @{ Expression = { $_.ws }; Descending = $true })
    $shown = @($rows | Select-Object -First $Limit)

    # Process metadata (path, owner, parent, command line) for the rows we emit.
    $selected = @{}
    foreach ($r in $shown) { $selected[[int]$r.pid] = $true }
    $meta = @{}
    $ownerMap = @{}
    try { $ownerMap = Get-OwnerMap -Ids @($shown | ForEach-Object { [int]$_.pid }) } catch { }
    try {
        foreach ($cp in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
            $op = [int]$cp.ProcessId
            if (-not $selected.ContainsKey($op)) { continue }
            $owner = ''
            if ($ownerMap.ContainsKey($op)) { $owner = [string]$ownerMap[$op] }
            $cmd = [string]$cp.CommandLine
            if ($cmd.Length -gt 400) { $cmd = $cmd.Substring(0, 400) + '...' }
            $meta[$op] = @{
                path = [string]$cp.ExecutablePath
                owner = $owner
                ppid = [int]$cp.ParentProcessId
                cmd = $cmd
            }
        }
    } catch { }

    $listenCount = 0
    $totalWs = 0
    foreach ($r in $shown) {
        $op = [int]$r.pid
        $path = ''; $owner = ''; $ppid = 0; $cmd = ''
        if ($meta.ContainsKey($op)) {
            $m = $meta[$op]
            $path = [string]$m.path; $owner = [string]$m.owner
            $ppid = [int]$m.ppid; $cmd = [string]$m.cmd
        }
        $portText = ''
        if ($r.ports.Count -gt 0) { $portText = ($r.ports -join ','); $listenCount++ }
        $totalWs += [int64]$r.ws
        Write-Evt 'proc' 'info' $r.name @{
            pid = $op; ppid = $ppid; name = $r.name; cpu = [double]$r.cpu
            ws = [int64]$r.ws; owner = $owner; path = $path; ports = $portText
            conns = [int]$r.conns; cmd = $cmd
        }
    }

    $summary = ('Process inventory complete - {0} of {1} process(es).' -f $shown.Count, $rows.Count)
    Write-Evt 'procdone' 'info' '' @{
        shown = $shown.Count; total = $rows.Count; listening = $listenCount; memory = $totalWs
    }
    Write-Evt 'log' 'ok' $summary
    Write-Evt 'done' 'ok' $summary @{ phase = 'processes'; shown = $shown.Count; total = $rows.Count }
}

function Invoke-Kill {
    param([int]$ProcId)

    if ($ProcId -le 4) {
        Write-Evt 'log' 'err' 'Refused: system idle and kernel processes cannot be terminated.'
        Write-Evt 'done' 'err' 'Refused.' @{ phase = 'kill'; pid = $ProcId }
        return
    }
    if ($ProcId -eq $PID) {
        Write-Evt 'log' 'err' 'Refused: that is the NetTruder engine process.'
        Write-Evt 'done' 'err' 'Refused.' @{ phase = 'kill'; pid = $ProcId }
        return
    }

    $p = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    if (-not $p) {
        Write-Evt 'log' 'err' ('No running process with pid {0}.' -f $ProcId)
        Write-Evt 'done' 'err' 'Not found.' @{ phase = 'kill'; pid = $ProcId }
        return
    }
    $name = [string]$p.ProcessName
    $lower = $name.ToLowerInvariant()
    $protected = @(
        'system', 'registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass',
        'svchost', 'fontdrvhost', 'lsaiso', 'msmpeng', 'mpdefendercore', 'securityhealthservice', 'sense'
    )
    if ($protected -contains $lower) {
        Write-Evt 'log' 'err' ('Refused: {0} (pid {1}) is a core system or security process. NetTruder will not weaken the host.' -f $name, $ProcId)
        Write-Evt 'done' 'err' 'Refused: protected process.' @{ phase = 'kill'; pid = $ProcId; name = $name }
        return
    }
    if (-not $Yes) {
        Write-Evt 'log' 'err' ('Refused: termination of {0} (pid {1}) needs explicit confirmation.' -f $name, $ProcId)
        Write-Evt 'done' 'err' 'Refused: no confirmation.' @{ phase = 'kill'; pid = $ProcId; name = $name }
        return
    }

    $path = ''
    try { $path = [string]$p.Path } catch { }
    try {
        Write-Audit 'kill' ('Terminate {0} (pid {1})' -f $name, $ProcId) @{ pid = $ProcId; name = $name; path = $path }
        Stop-Process -Id $ProcId -Force -ErrorAction Stop
        Write-Evt 'log' 'ok' ('Terminated {0} (pid {1}).' -f $name, $ProcId)
        Write-Evt 'done' 'ok' ('Terminated {0} (pid {1}).' -f $name, $ProcId) @{ phase = 'kill'; pid = $ProcId; name = $name }
    } catch {
        Write-Evt 'log' 'err' ('Could not terminate pid {0}: {1}' -f $ProcId, $_.Exception.Message)
        Write-Evt 'done' 'err' 'Terminate failed.' @{ phase = 'kill'; pid = $ProcId; name = $name }
    }
}

function Invoke-Research {
    $root = Split-Path -Parent $script:EngineDir
    $lab = Join-Path $root 'research\Test-NetTruderPosture.ps1'
    $dir = $LabDir
    if ([string]::IsNullOrWhiteSpace($dir)) { $dir = Join-Path $script:Root 'lab' }

    Write-Audit 'research' ('LOLBAS coverage inventory (probes={0})' -f [bool]$Probes) @{ lab = $lab; outDir = $dir }

    if (-not (Test-Path -LiteralPath $lab)) {
        Write-Evt 'log' 'err' ('Research lab not found: ' + $lab)
        Write-Evt 'done' 'err' 'Research module is unavailable.' @{ phase = 'research'; reason = 'missing-lab' }
        return
    }
    if ($Probes -and -not $Yes) {
        Write-Evt 'log' 'warn' 'Marker probes need explicit confirmation. Re-run with probes and consent.'
        Write-Evt 'done' 'err' 'Marker probes were not run.' @{ phase = 'research'; reason = 'no-consent' }
        return
    }

    try {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    } catch {
        Write-Evt 'log' 'err' ('Could not create the report folder: ' + $_.Exception.Message)
        Write-Evt 'done' 'err' 'Report folder unavailable.' @{ phase = 'research'; reason = 'no-outdir' }
        return
    }

    $outFile = Join-Path $script:Runs ("{0}.lab.out.txt" -f $RunId)
    $errFile = Join-Path $script:Runs ("{0}.lab.err.txt" -f $RunId)
    $started = (Get-Date).AddSeconds(-2)

    $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -OutDir "{1}"' -f $lab, $dir
    if ($Probes) { $argLine += ' -RunMarkerProbes -Yes' }

    Write-Evt 'log' 'dim' ('Running research lab: ' + (Split-Path -Leaf $lab))
    if ($Probes) { Write-Evt 'log' 'warn' 'Marker probes are enabled: four inert scripts will run and log one line each.' }

    $exitCode = -1
    try {
        $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -WindowStyle Hidden `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile -PassThru -ErrorAction Stop
        if ($proc.WaitForExit(180000)) {
            $exitCode = [int]$proc.ExitCode
        } else {
            try { $proc.Kill() } catch { }
            Write-Evt 'log' 'warn' 'Research lab timed out after 180 seconds.'
        }
    } catch {
        Write-Evt 'log' 'err' ('Could not start the research lab: ' + $_.Exception.Message)
        Write-Evt 'done' 'err' 'Research lab did not run.' @{ phase = 'research'; reason = 'spawn-failed' }
        return
    }
    Write-Evt 'log' 'dim' ('Research lab exit code: ' + $exitCode)

    $json = $null
    try {
        $json = Get-ChildItem -LiteralPath $dir -Filter 'lolbas-posture-*.json' -ErrorAction Stop |
            Where-Object { $_.LastWriteTime -ge $started } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    } catch { }

    if (-not $json) {
        $tail = ''
        try { $tail = ((Get-Content -LiteralPath $errFile -ErrorAction Stop | Select-Object -Last 3) -join ' ') } catch { }
        if ($tail) { Write-Evt 'log' 'err' ('lab stderr: ' + $tail) }
        Write-Evt 'done' 'err' 'No report was produced. The lab may be blocked by policy.' @{ phase = 'research'; reason = 'no-report' }
        return
    }

    $report = $null
    try {
        $report = Get-Content -LiteralPath $json.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Write-Evt 'log' 'err' ('Could not parse the report: ' + $_.Exception.Message)
        Write-Evt 'done' 'err' 'Report parse failed.' @{ phase = 'research'; reason = 'bad-report' }
        return
    }

    $asrTotal = 0; $asrBlock = 0; $asrAudit = 0
    if ($report.asr) {
        $asrTotal = [int]$report.asr.total
        $asrBlock = [int]$report.asr.block
        $asrAudit = [int]$report.asr.audit
    }
    $psLogText = 'absent'
    if ($report.powershellLog) { $psLogText = ('enabled={0} records={1}' -f $report.powershellLog.enabled, $report.powershellLog.records) }
    $sysmonText = 'not present'
    if ($report.sysmonLog) { $sysmonText = ('enabled={0} records={1}' -f $report.sysmonLog.enabled, $report.sysmonLog.records) }

    $catalogs = @()
    foreach ($c in @($report.catalogs)) {
        if ($null -eq $c) { continue }
        $catalogs += @{ file = [string]$c.file; label = [string]$c.label; version = [string]$c.version; count = [int]$c.count }
    }
    $groups = @()
    foreach ($g in @($report.groups)) {
        if ($null -eq $g) { continue }
        $groups += @{ name = [string]$g.name; count = [int]$g.count }
    }
    $platforms = @()
    foreach ($p in @($report.platforms)) {
        if ($null -eq $p) { continue }
        $platforms += @{ name = [string]$p.name; count = [int]$p.count }
    }
    $wsl = @{ checked = $false; available = $false; distros = @(); readable = @(); error = '' }
    if ($report.wsl) {
        $wsl.checked = [bool]$report.wsl.checked
        $wsl.available = [bool]$report.wsl.available
        $wsl.error = [string]$report.wsl.error
        foreach ($d in @($report.wsl.distros)) { if ($d) { $wsl.distros += [string]$d } }
        foreach ($d in @($report.wsl.readable)) { if ($d) { $wsl.readable += [string]$d } }
    }
    $blockRows = @()
    foreach ($b in @($report.blocks)) {
        if ($null -eq $b) { continue }
        $variants = @()
        foreach ($v in @($b.variants)) {
            if ($null -eq $v) { continue }
            $variants += @{ cmd = [string]$v.cmd; result = [string]$v.result }
        }
        $blockRows += @{
            id = [string]$b.id; tech = [string]$b.tech; technique = [string]$b.technique
            host = [string]$b.host; kind = [string]$b.kind; product = [string]$b.product
            date = [string]$b.date; vector = [string]$b.vector; cmd = [string]$b.cmd
            result = [string]$b.result; signal = [string]$b.signal; scope = [string]$b.scope
            valid = [string]$b.valid; teaches = [string]$b.teaches; followup = [string]$b.followup
            detect = [string]$b.detect; variants = $variants
        }
    }

    Write-Evt 'resmeta' 'ok' 'Coverage inventory complete.' @{
        host = [string]$report.host
        user = [string]$report.user
        admin = [bool]$report.admin
        adminGroup = [bool]$report.adminGroup
        tokenElevated = [bool]$report.tokenElevated
        integrity = [string]$report.integrity
        elevationType = [string]$report.elevationType
        securityReadable = $(if ($report.proof -and $report.proof.elevation) { [bool]$report.proof.elevation.securityReadable } else { $false })
        securityHint = $(if ($report.proof -and $report.proof.elevation) { [string]$report.proof.elevation.securityHint } else { '' })
        securityError = $(if ($report.proof -and $report.proof.elevation) { [string]$report.proof.elevation.securityError } else { '' })
        privilegePresent = $(if ($report.proof -and $report.proof.elevation) { [bool]$report.proof.elevation.privilegePresent } else { $false })
        privilegeEnabled = $(if ($report.proof -and $report.proof.elevation) { $report.proof.elevation.privilegeEnabled } else { $null })
        windows = [string]$report.windows
        build = [string]$report.build
        powershell = [string]$report.powershell
        catalog = [string]$report.catalog
        catalogs = $catalogs
        groups = $groups
        platforms = $platforms
        wsl = $wsl
        blocks = $blockRows
        blockCount = [int]$report.blockCount
        generated = [string]$report.generated
        report = $json.FullName
        labDir = $dir
        probesRun = [bool]$Probes
        asrTotal = $asrTotal
        asrBlock = $asrBlock
        asrAudit = $asrAudit
        amsiProviders = [int]$report.amsiProviders
        wshRemote = [string]$report.wshRemote
        trustPolicy = [string]$report.trustPolicy
        psLog = $psLogText
        sysmonLog = $sysmonText
    }

    $ctlCount = 0
    foreach ($row in @($report.controlRows)) {
        if ($null -eq $row) { continue }
        $rowFix = @()
        foreach ($line in @($row.fix)) { if ($line) { $rowFix += [string]$line } }
        Write-Evt 'rescontrol' 'info' '' @{
            id = [string]$row.id
            name = [string]$row.name
            value = [bool]$row.value
            source = [string]$row.source
            detail = [string]$row.detail
            fix = $rowFix
            enable = [string]$row.enable
            native = [string]$row.native
            severity = [string]$row.severity
            badWhenOn = [bool]$row.badWhenOn
            neutral = [bool]$row.neutral
        }
        $ctlCount++
    }
    if ($ctlCount -eq 0) {
        Write-Evt 'log' 'warn' 'The report did not include a control-plane table. Re-run the updated lab.'
    }

    if ($report.telemetryDelta) {
        $td = $report.telemetryDelta
        $srcElev = $null
        if ($td.elevation) {
            $elevToken = [bool]$td.elevation.elevated
            if ($td.elevation.PSObject.Properties['tokenElevated']) { $elevToken = [bool]$td.elevation.tokenElevated }
            $srcElev = @{
                elevated = [bool]$td.elevation.elevated
                tokenElevated = $elevToken
                adminGroup = [bool]$td.elevation.adminGroup
                integrity = [string]$td.elevation.integrity
                elevationType = [string]$td.elevation.elevationType
                user = [string]$td.elevation.user
                securityReadable = [bool]$td.elevation.securityReadable
                securityError = [string]$td.elevation.securityError
                securityHint = [string]$td.elevation.securityHint
                auditpolReadable = [bool]$td.elevation.auditpolReadable
                auditpolError = [string]$td.elevation.auditpolError
                auditpolHint = [string]$td.elevation.auditpolHint
                privilegePresent = [bool]$td.elevation.privilegePresent
                privilegeAttempted = [bool]$td.elevation.privilegeAttempted
                privilegeEnabled = $td.elevation.privilegeEnabled
                privilegeAttemptResult = $td.elevation.privilegeAttemptResult
                sysmonReadable = [bool]$td.elevation.sysmonReadable
                sysmonError = [string]$td.elevation.sysmonError
            }
        }
        $sysmonAccessible = $false
        $sysmonMatched = 0
        $sysmonVerdict = ''
        if ($td.sysmon1) {
            $sysmonAccessible = [bool]$td.sysmon1.accessible
            $sysmonMatched = [int]$td.sysmon1.matched
            $sysmonVerdict = [string]$td.sysmon1.verdict
        }
        Write-Evt 'resproof' 'info' '' @{
            ran = [bool]$td.ran
            method = $(if ($report.proof) { [string]$report.proof.method } else { '' })
            caveat = $(if ($report.proof) { [string]$report.proof.caveat } else { '' })
            thirdPartyEdr = $(if ($report.proof) { [string]$report.proof.thirdPartyEdr } else { '' })
            measuredAt = $(if ($report.proof) { [string]$report.proof.measured } else { '' })
            processObserved = $td.measuredProcess
            contentObserved = $td.measuredContent
            processSource = [string]$td.processSource
            contentSource = [string]$td.contentSource
            elevation = $srcElev
            secAccessible = [bool]$td.sec4688.accessible
            secBefore = [int]$td.sec4688.before
            secAfter = [int]$td.sec4688.after
            secDelta = $td.sec4688.delta
            secMatched = [int]$td.sec4688.matched
            secVerdict = [string]$td.sec4688.verdict
            sysmonAccessible = $sysmonAccessible
            sysmonMatched = $sysmonMatched
            sysmonVerdict = $sysmonVerdict
            psAccessible = [bool]$td.ps4104.accessible
            psBefore = [int]$td.ps4104.before
            psAfter = [int]$td.ps4104.after
            psDelta = $td.ps4104.delta
            psMatched = [int]$td.ps4104.matched
            psVerdict = [string]$td.ps4104.verdict
        }
    }

    foreach ($t in @($report.techniques)) {
        if ($null -eq $t) { continue }
        $hard = @()
        foreach ($h in @($t.hardening)) { if ($h) { $hard += [string]$h } }
        $fix = @()
        foreach ($h in @($t.fix)) { if ($h) { $fix += [string]$h } }
        $tree = @()
        foreach ($s in @($t.tree)) {
            if ($null -eq $s) { continue }
            $tree += @{
                s = [string]$s.s; t = [string]$s.t; p = [string]$s.p
                a = [string]$s.a; d = [string]$s.d; c = [string]$s.c
            }
        }
        $asr = @()
        foreach ($a in @($t.asr)) {
            if ($null -eq $a) { continue }
            $asr += @{ g = [string]$a.g; n = [string]$a.n }
        }
        $cmdMatch = @()
        $cmdWhy = ''
        if ($t.cmd) {
            foreach ($m in @($t.cmd.m)) { if ($m) { $cmdMatch += [string]$m } }
            $cmdWhy = [string]$t.cmd.w
        }
        $techBlocks = @()
        foreach ($b in @($t.blocks)) {
            if ($null -eq $b) { continue }
            $techBlocks += @{
                id = [string]$b.id; kind = [string]$b.kind; result = [string]$b.result
                host = [string]$b.host; cmd = [string]$b.cmd; signal = [string]$b.signal
                product = [string]$b.product; scope = [string]$b.scope
                valid = [string]$b.valid; teaches = [string]$b.teaches; followup = [string]$b.followup
                detect = [string]$b.detect
            }
        }
        $present = $null
        if ($null -ne $t.present) { $present = [bool]$t.present }
        Write-Evt 'restech' 'info' '' @{
            id = [string]$t.id
            name = [string]$t.name
            host = [string]$t.host
            family = [string]$t.family
            platform = [string]$t.platform
            group = [string]$t.group
            method = [string]$t.method
            catalog = [string]$t.catalog
            risk = [string]$t.risk
            present = $present
            presenceNote = [string]$t.presenceNote
            signature = [string]$t.signature
            signer = [string]$t.signer
            version = [string]$t.version
            path = [string]$t.path
            gap = [string]$t.gap
            basis = [string]$t.basis
            signals = [string]$t.signals
            abuse = [string]$t.abuse
            detection = [string]$t.detection
            hardening = $hard
            fix = $fix
            tree = $tree
            cmdMatch = $cmdMatch
            cmdWhy = $cmdWhy
            asr = $asr
            netWatch = [string]$t.net.w
            netPorts = [string]$t.net.ports
            blocks = $techBlocks
        }
    }

    foreach ($f in @($report.findings)) {
        if ($null -eq $f) { continue }
        $fFix = @()
        foreach ($line in @($f.fix)) { if ($line) { $fFix += [string]$line } }
        Write-Evt 'resfind' 'info' '' @{
            severity = [string]$f.severity
            title = [string]$f.title
            detail = [string]$f.detail
            control = [string]$f.control
            fix = $fFix
            enable = [string]$f.enable
            native = [string]$f.native
        }
    }

    foreach ($pr in @($report.probes)) {
        if ($null -eq $pr) { continue }
        Write-Evt 'resprobe' 'info' '' @{
            probe = [string]$pr.probe; host = [string]$pr.host
            executed = [bool]$pr.executed; marker = [bool]$pr.marker; error = [string]$pr.error
        }
    }

    $techs = @($report.techniques)
    $findings = @($report.findings)
    $probes = @($report.probes)
    $counts = @{ 'OK' = 0; 'CONTENT GAP' = 0; 'NETWORK GAP' = 0; 'BLIND' = 0; 'NOT EVALUATED' = 0; 'LINUX GAP' = 0 }
    foreach ($t in $techs) {
        $g = [string]$t.gap
        if ($g -eq 'NOT EVALUATED') { $counts['NOT EVALUATED']++ }
        elseif ($g -eq 'LINUX GAP') { $counts['LINUX GAP']++ }
        elseif ($counts.ContainsKey($g)) { $counts[$g]++ }
    }

    $summary = ('Research inventory - {0} technique(s), {1} BLIND, {2} LINUX GAP, {3} NOT EVALUATED, {4} finding(s)' -f $techs.Count, $counts['BLIND'], $counts['LINUX GAP'], $counts['NOT EVALUATED'], $findings.Count)
    Write-Evt 'log' 'ok' $summary
    Write-Evt 'log' 'dim' ('Report: ' + $json.FullName)
    Write-Evt 'done' 'ok' $summary @{
        phase = 'research'
        techniques = $techs.Count
        findings = $findings.Count
        probes = $probes.Count
        probesRun = [bool]$Probes
        blocks = $blockRows.Count
        ok = $counts['OK']
        content = $counts['CONTENT GAP']
        network = $counts['NETWORK GAP']
        blind = $counts['BLIND']
        linuxGap = $counts['LINUX GAP']
        notEvaluated = $counts['NOT EVALUATED']
        report = $json.FullName
        labDir = $dir
    }

    Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
}

# ===========================================================================
# Web posture - passive, unauthenticated GET/OPTIONS analysis only.
# No exploitation, no payloads, no fuzzing loop, no authentication bypass.
# ===========================================================================
function Get-WebHeader {
    param($Headers, [string]$Name)
    if ($null -eq $Headers) { return '' }
    foreach ($k in @($Headers.Keys)) {
        if ([string]$k -ieq $Name) { return [string]$Headers[$k] }
    }
    return ''
}

function Invoke-WebFetch {
    param(
        [string]$Url,
        [string]$Method = 'GET',
        [int]$TimeoutMs = 6000,
        [hashtable]$Headers = @{}
    )
    $r = @{
        ok = $false; status = 0; url = $Url; method = $Method
        headers = @{}; setcookie = @(); body = ''; length = 0
        error = ''; ms = 0; contenttype = ''
    }
    $resp = $null
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = $Method
        $req.Timeout = $TimeoutMs
        $req.ReadWriteTimeout = $TimeoutMs
        $req.AllowAutoRedirect = $false
        $req.UserAgent = 'NetTruder/1.1 defensive-web-posture'
        try {
            $req.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
        } catch { }
        foreach ($k in @($Headers.Keys)) {
            try {
                if ([string]$k -ieq 'Host') { $req.Host = [string]$Headers[$k] }
                else { $req.Headers.Add([string]$k, [string]$Headers[$k]) }
            } catch { }
        }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $resp = $req.GetResponse()
        $sw.Stop()
        $r.ok = $true
        $r.ms = $sw.ElapsedMilliseconds
        $r.status = [int]$resp.StatusCode
        $r.contenttype = [string]$resp.ContentType
        foreach ($k in @($resp.Headers.AllKeys)) {
            try { $r.headers[[string]$k] = [string]$resp.Headers[$k] } catch { }
        }
        try {
            $cookies = @($resp.Headers.GetValues('Set-Cookie'))
            if ($cookies.Count -gt 0) { $r.setcookie = $cookies }
        } catch { }
        if ($Method -ne 'HEAD') {
            $stream = $resp.GetResponseStream()
            $reader = New-Object IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            try { $body = $reader.ReadToEnd() } finally { $reader.Close() }
            if ($null -eq $body) { $body = '' }
            if ($body.Length -gt 524288) { $body = $body.Substring(0, 524288) }
            $r.body = $body
            $r.length = $body.Length
        }
    } catch [System.Net.WebException] {
        $we = $_.Exception
        $r.error = $we.Message
        try {
            if ($we.Response) {
                $resp = $we.Response
                $r.status = [int]$resp.StatusCode
                foreach ($k in @($resp.Headers.AllKeys)) {
                    try { $r.headers[[string]$k] = [string]$resp.Headers[$k] } catch { }
                }
                try {
                    $cookies = @($resp.Headers.GetValues('Set-Cookie'))
                    if ($cookies.Count -gt 0) { $r.setcookie = $cookies }
                } catch { }
                if ($Method -ne 'HEAD') {
                    $stream = $resp.GetResponseStream()
                    $reader = New-Object IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
                    try { $body = $reader.ReadToEnd() } finally { $reader.Close() }
                    if ($body.Length -gt 524288) { $body = $body.Substring(0, 524288) }
                    $r.body = $body
                    $r.length = $body.Length
                }
            }
        } catch { }
    } catch {
        $r.error = $_.Exception.Message
    } finally {
        if ($resp) { try { $resp.Close() } catch { } }
    }
    return $r
}

function Get-TlsInfo {
    param([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 6000)
    $o = @{
        ok = $false; protocol = ''; cipher = ''; hash = ''; keyx = ''
        subject = ''; issuer = ''; expires = ''; days = 0; error = ''
    }
    $tcp = $null
    $ssl = $null
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { throw 'TLS connect timed out' }
        $tcp.EndConnect($iar)
        $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) return $true }
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $cb)
        $ssl.AuthenticateAsClient($HostName)
        $o.ok = $true
        $o.protocol = [string]$ssl.SslProtocol
        $o.cipher = [string]$ssl.CipherAlgorithm
        $o.hash = [string]$ssl.HashAlgorithm
        $o.keyx = [string]$ssl.KeyExchangeAlgorithm
        if ($ssl.RemoteCertificate) {
            $c2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $o.subject = $c2.Subject
            $o.issuer = $c2.Issuer
            $o.expires = $c2.NotAfter.ToString('yyyy-MM-dd')
            $o.days = [int]($c2.NotAfter - (Get-Date)).TotalDays
        }
    } catch {
        $o.error = $_.Exception.Message
    } finally {
        if ($ssl) { try { $ssl.Close() } catch { } }
        if ($tcp) { try { $tcp.Close() } catch { } }
    }
    return $o
}

function Get-WebTargets {
    param([string]$Spec, [switch]$AllowPublic)
    if ([string]::IsNullOrWhiteSpace($Spec)) { return @() }
    $items = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($raw in ($Spec -split '[,\s]+')) {
        $s = $raw.Trim()
        if (-not $s) { continue }
        if ($s -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $s = 'http://' + $s }
        $u = $null
        if (-not [Uri]::TryCreate($s, [UriKind]::Absolute, [ref]$u)) { continue }
        if ($u.Scheme -notin @('http', 'https')) { continue }
        $hostName = $u.Host
        $isPriv = $false
        if ($hostName -ieq 'localhost') { $isPriv = $true }
        else {
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($hostName, [ref]$ip)) {
                $isPriv = Test-PrivateIp $hostName
            } else {
                try {
                    foreach ($a in @([System.Net.Dns]::GetHostAddresses($hostName))) {
                        if (Test-PrivateIp $a.IPAddressToString) { $isPriv = $true; break }
                    }
                } catch { $isPriv = $false }
            }
        }
        if (-not $AllowPublic -and -not $isPriv) {
            Write-Evt 'log' 'warn' ('Web target skipped (public host needs -AllowPublic): ' + $u.Host)
            continue
        }
        $port = $u.Port
        if ($port -le 0) { if ($u.Scheme -eq 'https') { $port = 443 } else { $port = 80 } }
        $key = $u.AbsoluteUri
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$items.Add(@{
            url = $u.AbsoluteUri; scheme = $u.Scheme; host = $u.Host
            port = $port; path = $u.AbsolutePath
        })
    }
    return @($items)
}

function Add-WebFinding {
    param(
        $List, $Seen,
        [string]$Id, [string]$Sev, [string]$Title, [string]$Url,
        [string]$Owasp, [string]$Cwe, [string]$Evidence, [string]$Fix,
        [string]$Research = '', [string]$Confidence = 'medium'
    )
    $key = $Id + '|' + $Url + '|' + $Title
    if ($Seen.ContainsKey($key)) { return }
    $Seen[$key] = $true
    [void]$List.Add(@{
        id = $Id; sev = $Sev; title = $Title; url = $Url
        owasp = $Owasp; cwe = $Cwe; evidence = $Evidence; fix = $Fix
        research = $Research; confidence = $Confidence
    })
}

function Get-MaskedText {
    param([string]$Text, [int]$Max = 240)
    if (-not $Text) { return '' }
    $s = [string]$Text
    $s = $s -replace '(?i)([:=]\s*["''])[^"'']{6,}(["''])', '$1***$2'
    $s = $s -replace '(?i)(api[_-]?key|secret|password|passwd|token|authorization)(\s*[:=]\s*)[^\s,;]{6,}', '$1$2***'
    $s = $s -replace '(?i)(-----BEGIN [A-Z ]+PRIVATE KEY-----)', '***PRIVATE KEY***'
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...' }
    return $s
}

function Count-ResearchFindings {
    param($List, [string[]]$Categories)
    $n = 0
    foreach ($x in @($List)) { if ($Categories -contains [string]$x.research) { $n++ } }
    return $n
}

function Get-HtmlAttr {
    param([string]$Attrs, [string]$Name)
    $rx = '(?i)\b' + [regex]::Escape($Name) + '\s*=\s*(?:"([^"]*)"|''([^'']*)''|([^\s>]+))'
    $m = [regex]::Match([string]$Attrs, $rx)
    if ($m.Success) { return ($m.Groups[1].Value + $m.Groups[2].Value + $m.Groups[3].Value) }
    return ''
}

function Get-ZapAdapter {
    $candidates = New-Object System.Collections.ArrayList
    $roots = New-Object System.Collections.ArrayList
    $pf = [string]$env:ProgramFiles
    $pf86 = [string]${env:ProgramFiles(x86)}
    $lad = [string]$env:LOCALAPPDATA
    if ($pf) {
        [void]$roots.Add((Join-Path $pf 'ZAP\Zed Attack Proxy\zap.bat'))
        [void]$roots.Add((Join-Path $pf 'ZAP\zap.bat'))
    }
    if ($pf86) {
        [void]$roots.Add((Join-Path $pf86 'ZAP\Zed Attack Proxy\zap.bat'))
        [void]$roots.Add((Join-Path $pf86 'ZAP\zap.bat'))
    }
    if ($lad) {
        [void]$roots.Add((Join-Path $lad 'Programs\ZAP\Zed Attack Proxy\zap.bat'))
        [void]$roots.Add((Join-Path $lad 'Programs\ZAP\zap.bat'))
    }
    [void]$roots.Add('C:\ZAP\zap.bat')
    [void]$roots.Add('C:\tools\ZAP\zap.bat')
    [void]$roots.Add('C:\tools\zap\zap.bat')
    foreach ($p in $roots) {
        if ($p -and (Test-Path -LiteralPath $p)) { [void]$candidates.Add($p) }
    }
    $cmd = $null
    try { $cmd = Get-Command 'zap.bat' -ErrorAction SilentlyContinue } catch { }
    if (-not $cmd) { try { $cmd = Get-Command 'zap.exe' -ErrorAction SilentlyContinue } catch { } }
    if ($cmd -and $cmd.Source) { [void]$candidates.Add([string]$cmd.Source) }
    $docker = $null
    try { $docker = Get-Command 'docker.exe' -ErrorAction SilentlyContinue } catch { }
    $path = ''
    if ($candidates.Count -gt 0) { $path = [string]$candidates[0] }
    $available = [bool]($path -ne '')
    $baseline = ''
    $active = ''
    if ($available) {
        $baseline = '& "' + $path + '" -cmd -quickurl "<url>" -quickout "<report.html>" -quickprogress'
        $active = '& "' + $path + '" -cmd -quickurl "<url>" -quickout "<report.html>" -quickprogress -quickscan'
    } elseif ($docker) {
        $baseline = 'docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "<url>" -r "<report.html>"'
        $active = 'docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t "<url>" -r "<report.html>"'
    }
    return @{
        available = $available
        path = $path
        docker = [bool]$docker
        baseline = $baseline
        active = $active
        note = 'NetTruder never launches ZAP automatically. Copy the baseline command only after you have written authorisation for the target. Active scanning is intrusive: use it only on a host you own.'
        checks = @(
            'Passive: security headers, cookies, TLS, banners, information disclosure',
            'Spider: crawl links and forms to build the site tree',
            'Passive scan: missing headers, cookie flags, disclosure, mixed content',
            'Active scan (authorised only): injection, XSS, path traversal, SSRF',
            'Report: HTML/JSON with OWASP categories and evidence'
        )
    }
}

function Invoke-WebScan {
    $targets = @(Get-WebTargets -Spec $Url -AllowPublic:$AllowPublic)
    $zap = Get-ZapAdapter
    $policy = 'Passive GET/OPTIONS and a short list of unauthenticated paths. No exploitation, no fuzzing, no auth bypass, no payloads. Public hosts require -AllowPublic.'
    Write-Audit 'webscan' ('Web posture check ({0} target(s))' -f $targets.Count) @{ targets = $Url; allowPublic = [bool]$AllowPublic }

    if ($targets.Count -eq 0) {
        Write-Evt 'log' 'err' 'No usable web target. Enter a loopback/private URL, or add -AllowPublic for an authorised public host.'
        Write-Evt 'zap' 'info' '' $zap
        Write-Evt 'done' 'err' 'Web scan had no target.' @{ phase = 'webscan'; targets = 0; policy = $policy }
        return
    }

    Write-Evt 'log' 'ok' ('Web posture start - {0} target(s)' -f $targets.Count)
    Write-Evt 'webmeta' 'info' '' @{
        targetCount = $targets.Count
        targets = @($targets)
        allowPublic = [bool]$AllowPublic
        zap = $zap
        policy = $policy
        window = (Get-Date).ToString('s')
    }

    $oldCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $script:WebTlsErrors = @()
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($sender, $cert, $chain, $errors)
        if ($errors -ne [System.Net.Security.SslPolicyErrors]::None) {
            $script:WebTlsErrors += [string]$errors
        }
        return $true
    }

    $grandFindings = 0
    $grandScore = 0
    try {
        foreach ($t in $targets) {
            $script:WebTlsErrors = @()
            $findings = New-Object System.Collections.ArrayList
            $seenFinding = @{}
            $base = $t.scheme + '://' + $t.host + ':' + [string]$t.port
            $root = Invoke-WebFetch -Url $t.url
            $body = [string]$root.body
            $h = $root.headers
            $tls = $null
            if ($t.scheme -eq 'https') { $tls = Get-TlsInfo -HostName $t.host -Port $t.port }

            $title = ''
            $tm = [regex]::Match($body, '(?is)<title[^>]*>(.*?)</title>')
            if ($tm.Success) { $title = ($tm.Groups[1].Value -replace '\s+', ' ').Trim() }
            if ($title.Length -gt 120) { $title = $title.Substring(0, 120) + '...' }

            if (-not $root.ok) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-000' 'high' 'Web target did not answer' $t.url 'A05:2021 Security Misconfiguration' 'CWE-16' $root.error 'Confirm the service is running, the URL scheme/port is correct, and the host is in scope.' 'web-availability' 'high'
            }

            # Header, body, path and CORS checks are only claims about a response
            # that was actually received. An unreachable host is reported once by
            # NT-WEB-000; missing headers are NOT EVALUATED, not a clean or dirty
            # result. Initialise the collectors so the tree/flow events stay valid.
            $forms = New-Object System.Collections.ArrayList
            $scripts = New-Object System.Collections.ArrayList
            $links = New-Object System.Collections.ArrayList
            $pathNodes = New-Object System.Collections.ArrayList
            if ($root.ok) {

            if ($t.scheme -eq 'http') {
                Add-WebFinding $findings $seenFinding 'NT-WEB-001' 'high' 'Site served over cleartext HTTP' $t.url 'A02:2021 Cryptographic Failures' 'CWE-319' ('status ' + $root.status + ' from ' + $t.url) 'Serve the site over HTTPS with a valid certificate and redirect HTTP to HTTPS (301). Never send credentials or tokens over HTTP.' 'web-tls-https' 'high'
            }

            if ($tls -and -not $tls.ok) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-002' 'high' 'TLS handshake failed' $t.url 'A02:2021 Cryptographic Failures' 'CWE-295' $tls.error 'Verify the certificate chain, hostname and TLS version. Do not disable certificate validation in the client.' 'web-tls-https' 'high'
            }
            if ($tls -and $tls.ok) {
                if ($tls.protocol -match 'Ssl2|Ssl3|Tls$|Tls11') {
                    $sev = 'med'
                    if ($tls.protocol -match 'Ssl2|Ssl3|Tls$') { $sev = 'high' }
                    Add-WebFinding $findings $seenFinding 'NT-WEB-003' $sev ('Weak TLS protocol: ' + $tls.protocol) $t.url 'A02:2021 Cryptographic Failures' 'CWE-326' ('negotiated ' + $tls.protocol + ' / ' + $tls.cipher) 'Require TLS 1.2 or newer and remove legacy protocol/cipher suites from the listener.' 'web-tls-https' 'high'
                }
                if ($tls.days -lt 0) {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-004' 'high' 'TLS certificate expired' $t.url 'A02:2021 Cryptographic Failures' 'CWE-298' ('expired ' + $tls.expires) 'Renew and deploy the certificate, then monitor expiry.' 'web-tls-https' 'high'
                } elseif ($tls.days -lt 30) {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-005' 'med' ('TLS certificate expires in ' + $tls.days + ' day(s)') $t.url 'A02:2021 Cryptographic Failures' 'CWE-298' ('expires ' + $tls.expires) 'Renew the certificate and add expiry monitoring.' 'web-tls-https' 'high'
                }
                if ($tls.subject -and $tls.subject -eq $tls.issuer) {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-006' 'med' 'Self-signed TLS certificate' $t.url 'A02:2021 Cryptographic Failures' 'CWE-295' $tls.subject 'Use a certificate from a trusted CA. On a lab host, document the exception and pin it only for the test client.' 'web-tls-https' 'high'
                }
            }
            if ($script:WebTlsErrors.Count -gt 0) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-007' 'high' 'TLS certificate validation error' $t.url 'A02:2021 Cryptographic Failures' 'CWE-295' (@($script:WebTlsErrors) -join '; ') 'Fix the certificate chain/hostname. Do not ship clients that ignore validation errors.' 'web-tls-https' 'high'
            }

            $hsts = Get-WebHeader $h 'Strict-Transport-Security'
            $csp = Get-WebHeader $h 'Content-Security-Policy'
            $xfo = Get-WebHeader $h 'X-Frame-Options'
            $xcto = Get-WebHeader $h 'X-Content-Type-Options'
            $ref = Get-WebHeader $h 'Referrer-Policy'
            $perm = Get-WebHeader $h 'Permissions-Policy'
            $coop = Get-WebHeader $h 'Cross-Origin-Opener-Policy'

            if ($t.scheme -eq 'https' -and -not $hsts) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-010' 'med' 'Missing HSTS header' $t.url 'A05:2021 Security Misconfiguration' 'CWE-319' 'Strict-Transport-Security not present' 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains after HTTPS is stable on every subdomain.' 'web-headers' 'high'
            } elseif ($hsts) {
                $hm = [regex]::Match($hsts, '(?i)max-age\s*=\s*(\d+)')
                if ($hm.Success -and [int]$hm.Groups[1].Value -lt 15552000) {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-011' 'low' 'HSTS max-age is short' $t.url 'A05:2021 Security Misconfiguration' 'CWE-319' $hsts 'Use max-age of at least 15552000 (180 days); 31536000 is common.' 'web-headers' 'high'
                }
            }
            if (-not $csp) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-012' 'med' 'Missing Content-Security-Policy' $t.url 'A05:2021 Security Misconfiguration' 'CWE-693' 'Content-Security-Policy not present' 'Deploy a restrictive CSP with nonces or hashes. Start in report-only, then enforce. Avoid unsafe-inline and unsafe-eval.' 'web-headers' 'high'
            } else {
                if ($csp -match '(?i)unsafe-inline') {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-013' 'med' 'CSP allows unsafe-inline' $t.url 'A05:2021 Security Misconfiguration' 'CWE-693' $csp 'Replace inline scripts/styles with nonces or hashes and remove unsafe-inline.' 'web-headers' 'high'
                }
                if ($csp -match '(?i)unsafe-eval') {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-014' 'med' 'CSP allows unsafe-eval' $t.url 'A05:2021 Security Misconfiguration' 'CWE-693' $csp 'Remove unsafe-eval and replace string-evaluated code with normal functions.' 'web-headers' 'high'
                }
                if ($csp -match '(?i)default-src\s+\*') {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-015' 'med' 'CSP default-src is wildcard' $t.url 'A05:2021 Security Misconfiguration' 'CWE-693' $csp 'List only the required origins. Do not use * for default-src or script-src.' 'web-headers' 'high'
                }
            }
            if (-not $xfo -and -not ($csp -match '(?i)frame-ancestors')) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-016' 'med' 'Clickjacking protection missing' $t.url 'A05:2021 Security Misconfiguration' 'CWE-1021' 'No X-Frame-Options and no CSP frame-ancestors' 'Send X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors (preferred).' 'web-headers' 'high'
            }
            if ($xcto -notmatch '(?i)nosniff') {
                Add-WebFinding $findings $seenFinding 'NT-WEB-017' 'low' 'X-Content-Type-Options missing or wrong' $t.url 'A05:2021 Security Misconfiguration' 'CWE-16' ('value: ' + $xcto) 'Send X-Content-Type-Options: nosniff.' 'web-headers' 'high'
            }
            if (-not $ref) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-018' 'low' 'Missing Referrer-Policy' $t.url 'A05:2021 Security Misconfiguration' 'CWE-200' 'Referrer-Policy not present' 'Send Referrer-Policy: strict-origin-when-cross-origin or no-referrer.' 'web-headers' 'high'
            }
            if (-not $perm) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-019' 'low' 'Missing Permissions-Policy' $t.url 'A05:2021 Security Misconfiguration' 'CWE-16' 'Permissions-Policy not present' 'Send Permissions-Policy to disable camera, microphone, geolocation and other features the site does not need.' 'web-headers' 'medium'
            }
            if (-not $coop) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-020' 'info' 'Cross-Origin-Opener-Policy not set' $t.url 'A05:2021 Security Misconfiguration' 'CWE-16' 'Cross-Origin-Opener-Policy not present' 'Set Cross-Origin-Opener-Policy: same-origin where the application does not need cross-window references.' 'web-headers' 'medium'
            }
            $banners = @()
            foreach ($bn in @('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator')) {
                $bv = Get-WebHeader $h $bn
                if ($bv) { $banners += ($bn + ': ' + $bv) }
            }
            if ($banners.Count -gt 0) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-021' 'low' 'Version/product banner disclosed' $t.url 'A05:2021 Security Misconfiguration' 'CWE-200' ($banners -join '; ') 'Remove or minimise Server/X-Powered-By headers at the reverse proxy or application server.' 'web-headers' 'high'
            }

            foreach ($sc in @($root.setcookie)) {
                if (-not $sc) { continue }
                $cookieName = (($sc -split '=', 2)[0]).Trim()
                $low = $sc.ToLower()
                $isSession = ($cookieName -match '(?i)sess|auth|token|jwt|sid|login|remember')
                if ($t.scheme -eq 'https' -and $low -notmatch '(^|;\s*)secure(\s*;|$)') {
                    Add-WebFinding $findings $seenFinding ('NT-WEB-030-' + $cookieName) 'med' ('Cookie without Secure: ' + $cookieName) $t.url 'A05:2021 Security Misconfiguration' 'CWE-614' $sc 'Set the Secure attribute on every cookie, especially session cookies.' 'web-cookies' 'high'
                }
                if ($isSession -and $low -notmatch '(^|;\s*)httponly(\s*;|$)') {
                    Add-WebFinding $findings $seenFinding ('NT-WEB-031-' + $cookieName) 'med' ('Session cookie without HttpOnly: ' + $cookieName) $t.url 'A07:2021 Identification and Authentication Failures' 'CWE-1004' $sc 'Set HttpOnly on session cookies so script cannot read them.' 'web-cookies' 'high'
                }
                if ($low -notmatch '(^|;\s*)samesite=') {
                    Add-WebFinding $findings $seenFinding ('NT-WEB-032-' + $cookieName) 'low' ('Cookie without SameSite: ' + $cookieName) $t.url 'A01:2021 Broken Access Control' 'CWE-1275' $sc 'Set SameSite=Lax or Strict. Use None only with Secure for a documented cross-site flow.' 'web-cookies' 'high'
                } elseif ($low -match 'samesite=none' -and $low -notmatch 'secure') {
                    Add-WebFinding $findings $seenFinding ('NT-WEB-033-' + $cookieName) 'med' ('SameSite=None without Secure: ' + $cookieName) $t.url 'A05:2021 Security Misconfiguration' 'CWE-614' $sc 'SameSite=None requires Secure.' 'web-cookies' 'high'
                }
            }

            $formMatches = [regex]::Matches($body, '(?is)<form\b([^>]*)>(.*?)</form>')
            $forms = New-Object System.Collections.ArrayList
            $formLimit = [Math]::Min($formMatches.Count, 20)
            for ($fi = 0; $fi -lt $formLimit; $fi++) {
                $fm = $formMatches[$fi]
                $attrs = $fm.Groups[1].Value
                $inner = $fm.Groups[2].Value
                $action = ''
                $am = [regex]::Match($attrs, '(?i)\baction\s*=\s*(?:"([^"]*)"|''([^'']*)''|([^\s>]+))')
                if ($am.Success) { $action = $am.Groups[1].Value + $am.Groups[2].Value + $am.Groups[3].Value }
                if (-not $action) { $action = $t.url }
                $method = 'get'
                $mm = [regex]::Match($attrs, '(?i)\bmethod\s*=\s*["'']?([a-z]+)')
                if ($mm.Success) { $method = $mm.Groups[1].Value.ToLower() }
                $hasPassword = [regex]::IsMatch($inner, '(?i)<input[^>]+type\s*=\s*["'']?password')
                $hasToken = [regex]::IsMatch($inner, '(?i)name\s*=\s*["''][^"'']*(csrf|token|nonce|authenticity)[^"'']*["'']')
                $fieldCount = ([regex]::Matches($inner, '(?i)<(input|select|textarea)\b')).Count
                [void]$forms.Add(@{ action = $action; method = $method; password = $hasPassword; token = $hasToken; fields = $fieldCount })
                if ($hasPassword -and $method -eq 'get') {
                    Add-WebFinding $findings $seenFinding ('NT-WEB-040-' + $fi) 'high' 'Password form submits with GET' $t.url 'A04:2021 Insecure Design' 'CWE-598' ('form ' + $fi + ' action ' + $action) 'Use POST for credentials and send them only over HTTPS.' 'web-forms' 'high'
                }
                if ($hasPassword -and $method -eq 'post' -and -not $hasToken) {
                    Add-WebFinding $findings $seenFinding ('NT-WEB-041-' + $fi) 'med' 'Login form has no visible CSRF token' $t.url 'A01:2021 Broken Access Control' 'CWE-352' ('form ' + $fi + ' action ' + $action) 'Add a per-session CSRF token (or SameSite cookies plus origin checks). Verify server-side.' 'web-forms' 'low'
                }
                if ($action -match '^http://' -and $t.scheme -eq 'https') {
                    Add-WebFinding $findings $seenFinding ('NT-WEB-042-' + $fi) 'high' 'Form posts to cleartext HTTP' $t.url 'A02:2021 Cryptographic Failures' 'CWE-319' $action 'Post to HTTPS only.' 'web-forms' 'high'
                }
                if ($hasPassword -and -not ($root.headers.ContainsKey('Cache-Control') -and [string]$root.headers['Cache-Control'] -match '(?i)no-store')) {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-043' 'low' 'Login page is cacheable' $t.url 'A05:2021 Security Misconfiguration' 'CWE-525' 'Cache-Control does not include no-store' 'Send Cache-Control: no-store on login and account pages.' 'web-forms' 'medium'
                }
            }

            $scriptMatches = [regex]::Matches($body, '(?is)<script\b([^>]*)>(.*?)</script>')
            $scripts = New-Object System.Collections.ArrayList
            $scriptLimit = [Math]::Min($scriptMatches.Count, 40)
            for ($si = 0; $si -lt $scriptLimit; $si++) {
                $sm = $scriptMatches[$si]
                $sattrs = $sm.Groups[1].Value
                $sinner = $sm.Groups[2].Value
                $src = Get-HtmlAttr $sattrs 'src'
                $integrity = Get-HtmlAttr $sattrs 'integrity'
                $crossorigin = Get-HtmlAttr $sattrs 'crossorigin'
                $stype = Get-HtmlAttr $sattrs 'type'
                $asyncFlag = [bool]($sattrs -match '(?i)\basync\b')
                $deferFlag = [bool]($sattrs -match '(?i)\bdefer\b')
                $kind = 'inline'
                $external = $false
                $risky = $false
                $codeMasked = Get-MaskedText $sinner 1600
                $attrsMasked = Get-MaskedText $sattrs.Trim() 400
                if ($src) {
                    $kind = 'external'
                    $external = ($src -match '^https?://')
                    [void]$scripts.Add(@{
                        index = $si; src = $src; inline = $false; bytes = 0; kind = $kind
                        type = $stype; integrity = $integrity; crossorigin = $crossorigin
                        async = $asyncFlag; defer = $deferFlag; external = $external
                        risky = $false; attrs = $attrsMasked; code = ''
                        note = 'External reference parsed from HTML; it was not fetched or executed.'
                    })
                    if ($src -match '^http://' -and $t.scheme -eq 'https') {
                        Add-WebFinding $findings $seenFinding ('NT-WEB-050-' + $si) 'high' 'Mixed content: script loaded over HTTP' $t.url 'A08:2021 Software and Data Integrity Failures' 'CWE-319' $src 'Load every script over HTTPS and add Subresource Integrity where the asset is cross-origin.' 'web-mixed-content' 'high'
                    }
                    if ($src -match '^https?://' -and -not $sattrs.ToLower().Contains('integrity=') -and -not $src.ToLower().Contains($t.host.ToLower())) {
                        Add-WebFinding $findings $seenFinding ('NT-WEB-051-' + $si) 'low' 'Cross-origin script without SRI' $t.url 'A08:2021 Software and Data Integrity Failures' 'CWE-353' $src 'Add integrity and crossorigin attributes, or self-host the dependency.' 'web-sri' 'medium'
                    }
                } else {
                    $risky = [bool]($sinner -match '(?i)\b(eval|document\.write|innerHTML)\s*\(')
                    [void]$scripts.Add(@{
                        index = $si; src = ''; inline = $true; bytes = $sinner.Length; kind = $kind
                        type = $stype; integrity = $integrity; crossorigin = $crossorigin
                        async = $asyncFlag; defer = $deferFlag; external = $false
                        risky = $risky; attrs = $attrsMasked; code = $codeMasked
                        note = 'Inline body is masked and capped at 1600 characters for safe review.'
                    })
                    if ($risky) {
                        Add-WebFinding $findings $seenFinding ('NT-WEB-052-' + $si) 'med' 'Inline script uses a risky DOM sink' $t.url 'A03:2021 Injection' 'CWE-79' ('inline script ' + $si + ' contains eval/document.write/innerHTML') 'Move code to modules, use textContent or a sanitizer, and remove eval/document.write. This is a static hint; confirm with a code review.' 'web-xss-dom' 'low'
                    }
                }
            }

            $links = New-Object System.Collections.ArrayList
            $linkMatches = [regex]::Matches($body, '(?is)<a\b([^>]*)>(.*?)</a>')
            $linkLimit = [Math]::Min($linkMatches.Count, 80)
            for ($li = 0; $li -lt $linkLimit; $li++) {
                $attrs = $linkMatches[$li].Groups[1].Value
                $inner = $linkMatches[$li].Groups[2].Value
                $href = Get-HtmlAttr $attrs 'href'
                if (-not $href) { continue }
                $rel = Get-HtmlAttr $attrs 'rel'
                $target = Get-HtmlAttr $attrs 'target'
                $linkText = [regex]::Replace($inner, '(?is)<[^>]+>', ' ')
                $linkText = Get-MaskedText (($linkText -replace '\s+', ' ').Trim()) 200
                $absolute = $href
                if ($href.StartsWith('/')) { $absolute = $base + $href }
                elseif ($href -notmatch '^[a-z][a-z0-9+.-]*:') { $absolute = $base + '/' + $href.TrimStart('/') }
                $scheme = ''
                if ($absolute -match '^([a-z][a-z0-9+.-]*):') { $scheme = $Matches[1].ToLower() }
                if ($href -match '^#') { $kind = 'fragment' }
                elseif ($href -match '^javascript:') { $kind = 'javascript' }
                elseif ($href -match '^(mailto|tel):') { $kind = $scheme }
                elseif ($absolute -match '^https?://' -and $absolute.ToLower().Contains($t.host.ToLower())) { $kind = 'internal' }
                elseif ($absolute -match '^https?://') { $kind = 'external' }
                else { $kind = 'relative' }
                $external = ($kind -eq 'external')
                if ($href -match '^javascript:') {
                    Add-WebFinding $findings $seenFinding ('NT-WEB-060-' + $li) 'low' 'javascript: link found' $t.url 'A03:2021 Injection' 'CWE-79' $href 'Use a button with an event handler instead of javascript: URLs.' 'web-xss-dom' 'medium'
                }
                [void]$links.Add(@{
                    index = $li; href = $href; absolute = $absolute; text = $linkText
                    rel = $rel; target = $target; scheme = $scheme; kind = $kind
                    external = $external; note = 'Parsed from HTML; NetTruder did not follow this link.'
                })
            }

            $comments = [regex]::Matches($body, '(?is)<!--(.*?)-->')
            $commentLimit = [Math]::Min($comments.Count, 20)
            for ($ci = 0; $ci -lt $commentLimit; $ci++) {
                $cv = $comments[$ci].Groups[1].Value
                if ($cv -match '(?i)(todo|fixme|password|passwd|secret|api[_-]?key|token|connectionstring)') {
                    $evidence = ($cv -replace '\s+', ' ').Trim()
                    if ($evidence.Length -gt 160) { $evidence = $evidence.Substring(0, 160) + '...' }
                    $evidence = $evidence -replace '(?i)([:=]\s*)[^\s]{6,}', '$1***'
                    Add-WebFinding $findings $seenFinding ('NT-WEB-070-' + $ci) 'low' 'Sensitive-looking HTML comment' $t.url 'A05:2021 Security Misconfiguration' 'CWE-200' $evidence 'Remove developer notes and secrets from production markup.' 'web-comments' 'medium'
                }
            }

            if ($body -match '(?i)(SQLSTATE\[|ORA-\d{4,}|Traceback \(most recent call last\)|Warning: mysql_|System\.Data\.SqlClient|at System\.Web\.)') {
                Add-WebFinding $findings $seenFinding 'NT-WEB-080' 'med' 'Error details disclosed in response' $t.url 'A05:2021 Security Misconfiguration' 'CWE-209' 'stack/database error signature found in the body' 'Return a generic error page; log details server-side; disable debug mode.' 'web-errors' 'medium'
            }
            if ($body -match '(?i)<title>\s*Index of\s*/') {
                Add-WebFinding $findings $seenFinding 'NT-WEB-081' 'high' 'Directory listing enabled' $t.url 'A01:2021 Broken Access Control' 'CWE-548' 'Index of / page detected' 'Disable directory browsing and remove the directory index.' 'web-directory' 'high'
            }

            $robots = Invoke-WebFetch -Url ($base + '/robots.txt') -TimeoutMs 4000
            if ($robots.status -eq 200 -and $robots.body -match '(?im)^\s*Disallow:\s*(\S+)') {
                $dis = @([regex]::Matches($robots.body, '(?im)^\s*Disallow:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value })
                $sensitive = @($dis | Where-Object { $_ -match '(?i)admin|backup|config|internal|private|dump|sql|old' })
                if ($sensitive.Count -gt 0) {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-082' 'low' 'robots.txt discloses sensitive paths' $t.url 'A05:2021 Security Misconfiguration' 'CWE-200' (($sensitive | Select-Object -First 8) -join ', ') 'Do not rely on robots.txt to protect a path. Require authentication and remove stale entries.' 'web-directory' 'medium'
                }
            }
            $secTxt = Invoke-WebFetch -Url ($base + '/.well-known/security.txt') -TimeoutMs 4000
            if ($secTxt.status -ne 200) {
                Add-WebFinding $findings $seenFinding 'NT-WEB-083' 'info' 'No security.txt contact' $t.url 'A09:2021 Security Logging and Monitoring Failures' 'CWE-1059' ('status ' + $secTxt.status) 'Publish /.well-known/security.txt with a monitored security contact.' 'web-sec-txt' 'high'
            }

            $probePaths = @('/.git/HEAD', '/.env', '/server-status', '/phpinfo.php', '/swagger-ui/index.html', '/actuator/health', '/web.config', '/backup.zip', '/wp-login.php', '/admin/')
            $pathNodes = New-Object System.Collections.ArrayList
            foreach ($p in $probePaths) {
                $u2 = $base + $p
                $r2 = Invoke-WebFetch -Url $u2 -TimeoutMs 4000
                if ($r2.status -eq 200) {
                    if ($p -eq '/.git/HEAD' -and $r2.body -match '^ref:') {
                        Add-WebFinding $findings $seenFinding ('NT-WEB-090-' + $p) 'high' 'Exposed .git metadata' $u2 'A01:2021 Broken Access Control' 'CWE-538' 'GET 200 and a git ref was returned' 'Block .git at the web server, remove the repository from the web root, and rotate any secrets that were committed.' 'web-exposure' 'high'
                    } elseif ($p -eq '/.env' -and $r2.body -match '(?m)^[A-Z0-9_]+\s*=') {
                        Add-WebFinding $findings $seenFinding ('NT-WEB-091-' + $p) 'high' 'Exposed .env file' $u2 'A01:2021 Broken Access Control' 'CWE-538' 'GET 200 and KEY=value content was returned' 'Block dotfiles, remove the file from the web root, and rotate every exposed secret.' 'web-exposure' 'high'
                    } elseif ($p -eq '/server-status' -and $r2.body -match '(?i)Apache Server Status') {
                        Add-WebFinding $findings $seenFinding 'NT-WEB-092' 'med' 'Apache server-status exposed' $u2 'A05:2021 Security Misconfiguration' 'CWE-16' 'server-status page returned' 'Restrict server-status to localhost or a management network.' 'web-exposure' 'high'
                    } elseif ($p -eq '/phpinfo.php' -and $r2.body -match '(?i)PHP Version') {
                        Add-WebFinding $findings $seenFinding 'NT-WEB-093' 'high' 'phpinfo() exposed' $u2 'A05:2021 Security Misconfiguration' 'CWE-16' 'phpinfo output returned' 'Remove phpinfo.php from production.' 'web-exposure' 'high'
                    } elseif ($p -eq '/swagger-ui/index.html' -and $r2.body -match '(?i)swagger') {
                        Add-WebFinding $findings $seenFinding 'NT-WEB-094' 'med' 'API documentation exposed' $u2 'A05:2021 Security Misconfiguration' 'CWE-16' 'Swagger UI returned' 'Require authentication for API docs, or disable them in production.' 'web-exposure' 'medium'
                    } elseif ($p -eq '/actuator/health' -and $r2.body -match '(?i)"status"') {
                        Add-WebFinding $findings $seenFinding 'NT-WEB-095' 'med' 'Actuator health endpoint exposed' $u2 'A05:2021 Security Misconfiguration' 'CWE-16' 'actuator health returned' 'Restrict actuator endpoints to the management network and require authentication.' 'web-exposure' 'medium'
                    } elseif ($p -eq '/web.config') {
                        Add-WebFinding $findings $seenFinding 'NT-WEB-096' 'high' 'web.config exposed' $u2 'A01:2021 Broken Access Control' 'CWE-538' 'GET 200 for web.config' 'Block configuration files at the web server and rotate connection strings.' 'web-exposure' 'high'
                    } elseif ($p -eq '/backup.zip') {
                        Add-WebFinding $findings $seenFinding 'NT-WEB-097' 'high' 'Backup archive exposed' $u2 'A01:2021 Broken Access Control' 'CWE-538' 'GET 200 for backup.zip' 'Remove backups from the web root and store them in access-controlled storage.' 'web-exposure' 'medium'
                    } elseif ($p -eq '/admin/') {
                        Add-WebFinding $findings $seenFinding 'NT-WEB-098' 'info' 'Administrative surface reachable' $u2 'A01:2021 Broken Access Control' 'CWE-284' 'GET 200 for /admin/' 'Verify that authentication and authorisation are enforced server-side; do not rely on a hidden URL.' 'web-access' 'medium'
                    } elseif ($p -eq '/wp-login.php') {
                        Add-WebFinding $findings $seenFinding 'NT-WEB-099' 'info' 'WordPress login reachable' $u2 'A07:2021 Identification and Authentication Failures' 'CWE-307' 'GET 200 for wp-login.php' 'Enforce MFA, rate limiting and a login allowlist; keep WordPress and plugins patched.' 'web-auth' 'medium'
                    }
                    [void]$pathNodes.Add(@{ path = $p; status = $r2.status; bytes = $r2.length; type = 'path'; sev = 'info' })
                }
                Start-Sleep -Milliseconds 60
            }

            $cors = Invoke-WebFetch -Url $t.url -Headers @{ Origin = 'https://nettruder.invalid' }
            $acao = Get-WebHeader $cors.headers 'Access-Control-Allow-Origin'
            $acac = Get-WebHeader $cors.headers 'Access-Control-Allow-Credentials'
            if ($acao -eq '*') {
                if ($acac -ieq 'true') {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-100' 'high' 'CORS wildcard with credentials' $t.url 'A01:2021 Broken Access Control' 'CWE-942' ('Access-Control-Allow-Origin: *; Credentials: ' + $acac) 'Never combine wildcard origin with credentials. Echo only an allowlisted origin after validation.' 'web-cors' 'high'
                } else {
                    Add-WebFinding $findings $seenFinding 'NT-WEB-101' 'low' 'CORS allows any origin' $t.url 'A01:2021 Broken Access Control' 'CWE-942' 'Access-Control-Allow-Origin: *' 'Restrict CORS to the origins that need it; keep credentials off for public data.' 'web-cors' 'high'
                }
            } elseif ($acao -ieq 'https://nettruder.invalid') {
                Add-WebFinding $findings $seenFinding 'NT-WEB-102' 'med' 'CORS reflects an arbitrary origin' $t.url 'A01:2021 Broken Access Control' 'CWE-942' $acao 'Validate the Origin against an allowlist instead of reflecting it.' 'web-cors' 'high'
            }

            $opt = Invoke-WebFetch -Url $t.url -Method 'OPTIONS'
            $allow = Get-WebHeader $opt.headers 'Allow'
            if ($allow -match '(?i)\bTRACE\b') {
                Add-WebFinding $findings $seenFinding 'NT-WEB-110' 'med' 'TRACE method enabled' $t.url 'A05:2021 Security Misconfiguration' 'CWE-16' $allow 'Disable TRACE and TRACK at the web server.' 'web-methods' 'high'
            }

            } # end: response-derived checks (only when the target answered)

            $score = 100
            foreach ($f in $findings) {
                if ($f.sev -eq 'high') { $score -= 22 }
                elseif ($f.sev -eq 'med') { $score -= 9 }
                elseif ($f.sev -eq 'low') { $score -= 3 }
            }
            if ($score -lt 0) { $score = 0 }
            $grade = 'A'
            if ($score -lt 90) { $grade = 'B' }
            if ($score -lt 75) { $grade = 'C' }
            if ($score -lt 55) { $grade = 'D' }
            if ($score -lt 35) { $grade = 'F' }
            if (-not $root.ok) { $grade = 'n/a' }

            $treeNodes = New-Object System.Collections.ArrayList
            $treeEdges = New-Object System.Collections.ArrayList
            [void]$treeNodes.Add(@{ id = 'root'; label = ($t.host + $t.path); type = 'page'; sev = 'info'; note = ('HTTP ' + $root.status) })
            $nodeIndex = 0
            foreach ($s in $scripts) {
                $nodeIndex++
                $nid = 'asset' + [string]$nodeIndex
                $label = $s.src
                if (-not $label) { $label = 'inline script (' + $s.bytes + ' bytes)' }
                $sev = 'info'
                if ($s.src -match '^http://' -and $t.scheme -eq 'https') { $sev = 'high' }
                [void]$treeNodes.Add(@{ id = $nid; label = $label; type = 'script'; sev = $sev; note = '' })
                [void]$treeEdges.Add(@{ from = 'root'; to = $nid; label = 'loads' })
            }
            foreach ($f2 in $forms) {
                $nodeIndex++
                $nid = 'form' + [string]$nodeIndex
                $label = $f2.method.ToUpper() + ' ' + $f2.action
                $sev = 'info'
                if ($f2.password) { $sev = 'med' }
                [void]$treeNodes.Add(@{ id = $nid; label = $label; type = 'form'; sev = $sev; note = ($f2.fields.ToString() + ' field(s)') })
                [void]$treeEdges.Add(@{ from = 'root'; to = $nid; label = 'submits' })
            }
            foreach ($lnk in ($links | Select-Object -First 24)) {
                if ($lnk -is [string]) { $linkHref = $lnk } else { $linkHref = [string]$lnk.href }
                if (-not $linkHref) { continue }
                if ($linkHref -match '^#' -or $linkHref -match '^(mailto|tel):' -or $linkHref -match '^javascript:') { continue }
                $nodeIndex++
                $nid = 'link' + [string]$nodeIndex
                [void]$treeNodes.Add(@{ id = $nid; label = $linkHref; type = 'link'; sev = 'info'; note = '' })
                [void]$treeEdges.Add(@{ from = 'root'; to = $nid; label = 'links' })
            }
            foreach ($pn in $pathNodes) {
                $nodeIndex++
                $nid = 'path' + [string]$nodeIndex
                [void]$treeNodes.Add(@{ id = $nid; label = $pn.path; type = 'path'; sev = $pn.sev; note = ('HTTP ' + $pn.status + ' / ' + $pn.bytes + ' bytes') })
                [void]$treeEdges.Add(@{ from = 'root'; to = $nid; label = 'probe' })
            }

            $headerCount = Count-ResearchFindings $findings @('web-headers', 'web-cors')
            $cookieCount = Count-ResearchFindings $findings @('web-cookies')
            $formCount = Count-ResearchFindings $findings @('web-forms', 'web-auth', 'web-access')
            $scriptCount = Count-ResearchFindings $findings @('web-mixed-content', 'web-sri', 'web-xss-dom')
            $exposureCount = Count-ResearchFindings $findings @('web-exposure', 'web-directory', 'web-errors', 'web-comments')
            $logCount = Count-ResearchFindings $findings @('web-sec-txt', 'web-availability')
            $headerEvidence = @()
            if ($csp) { $headerEvidence += 'CSP present' } else { $headerEvidence += 'CSP missing' }
            if ($hsts) { $headerEvidence += 'HSTS present' } else { $headerEvidence += 'HSTS missing' }
            if ($xfo -or ($csp -match '(?i)frame-ancestors')) { $headerEvidence += 'frame protection present' } else { $headerEvidence += 'frame protection missing' }

            $flowNodes = New-Object System.Collections.ArrayList
            $flowEdges = New-Object System.Collections.ArrayList
            [void]$flowNodes.Add(@{
                id = 'browser'; label = 'Browser'; type = 'client'; sev = 'info'
                detail = 'Operator-controlled client'
                evidence = 'The passive GET/OPTIONS request came from this console.'
                why = 'Everything to the right is inferred from the response returned to that client.'
                confidence = 'measured'; categories = @()
            })
            [void]$flowNodes.Add(@{
                id = 'tls'
                label = $(if ($t.scheme -eq 'https') { 'TLS transport' } else { 'HTTP cleartext' })
                type = 'transport'
                sev = $(if ($t.scheme -eq 'http') { 'high' } elseif ($tls -and -not $tls.ok) { 'high' } else { 'info' })
                detail = $(if ($tls -and $tls.ok) { $tls.protocol + ' / ' + $tls.cipher } else { 'not negotiated' })
                evidence = $(if ($root.ok) { ('HTTP status ' + [string]$root.status) } else { $root.error })
                why = 'Cleartext or weak transport exposes cookies, forms and script payloads to observers.'
                fix = 'Require TLS 1.2 or newer and redirect cleartext requests to HTTPS.'
                confidence = 'measured'; categories = @('web-tls-https', 'web-methods')
            })
            [void]$flowNodes.Add(@{
                id = 'app'; label = 'Web app'; type = 'app'; sev = 'info'
                detail = ('HTTP ' + $root.status + ' - ' + $title)
                evidence = ('Answered=' + $(if ($root.ok) { 'yes' } else { 'no' }) + ' / bytes=' + [string]$root.length)
                why = 'This is the origin that produced the fetched document and headers.'
                confidence = 'measured'; categories = @('web-availability', 'web-errors')
            })
            [void]$flowNodes.Add(@{
                id = 'headers'; label = 'Response headers'; type = 'headers'; sev = $(if ($headerCount -gt 0) { 'med' } else { 'info' })
                detail = ([string]$headerCount + ' header/cors finding(s)')
                evidence = (Get-MaskedText ($headerEvidence -join '; ') 180)
                why = 'Headers decide transport hardening, framing, referrer leakage and browser origin rules.'
                fix = 'Send HSTS, CSP, nosniff, referrer and frame-ancestors; restrict CORS to allowlisted origins.'
                confidence = 'measured'; categories = @('web-headers', 'web-cors', 'web-methods')
            })
            if (@($root.setcookie).Count -gt 0) {
                $cookieSamples = @($root.setcookie | Select-Object -First 3 | ForEach-Object { (Get-MaskedText ([string]$_) 90) })
                [void]$flowNodes.Add(@{
                    id = 'cookies'; label = 'Cookies / session'; type = 'identity'; sev = $(if ($cookieCount -gt 0) { 'med' } else { 'info' })
                    detail = ([string](@($root.setcookie).Count) + ' cookie(s), ' + [string]$cookieCount + ' finding(s)')
                    evidence = (Get-MaskedText ($cookieSamples -join '; ') 220)
                    why = 'Session cookies travel back on later requests; Secure, HttpOnly and SameSite limit exposure.'
                    fix = 'Set Secure, HttpOnly and SameSite=Lax or Strict on session cookies.'
                    confidence = 'measured'; categories = @('web-cookies')
                })
            }
            if ($forms.Count -gt 0) {
                $formSamples = @($forms | Select-Object -First 3 | ForEach-Object { ([string]$_.method).ToUpper() + ' ' + [string]$_.action })
                [void]$flowNodes.Add(@{
                    id = 'forms'; label = 'Forms / API'; type = 'api'; sev = $(if ($formCount -gt 0) { 'med' } else { 'info' })
                    detail = ([string]$forms.Count + ' form(s), ' + [string]$formCount + ' finding(s)')
                    evidence = (Get-MaskedText ($formSamples -join '; ') 220)
                    why = 'Forms are the visible input boundary; action and method are read from HTML, not tested.'
                    fix = 'Use POST over HTTPS for credentials and verify CSRF tokens server-side.'
                    confidence = 'measured'; categories = @('web-forms', 'web-auth', 'web-access')
                })
            }
            if ($scripts.Count -gt 0) {
                $scriptSamples = @($scripts | Select-Object -First 3 | ForEach-Object { if ($_.src) { [string]$_.src } else { 'inline ' + [string]$_.bytes + ' bytes' } })
                [void]$flowNodes.Add(@{
                    id = 'scripts'; label = 'Scripts (' + [string]$scripts.Count + ')'; type = 'script'; sev = $(if ($scriptCount -gt 0) { 'med' } else { 'info' })
                    detail = ([string]$scriptCount + ' script finding(s)')
                    evidence = (Get-MaskedText ($scriptSamples -join '; ') 220)
                    why = 'External references and inline bodies shape browser behaviour; none were executed here.'
                    fix = 'Use HTTPS and SRI for cross-origin scripts; remove eval, document.write and innerHTML sinks.'
                    confidence = 'measured'; categories = @('web-mixed-content', 'web-sri', 'web-xss-dom')
                })
            }
            if ($links.Count -gt 0) {
                $linkSamples = @($links | Select-Object -First 3 | ForEach-Object { if ($_ -is [string]) { [string]$_ } else { [string]$_.href } })
                [void]$flowNodes.Add(@{
                    id = 'links'; label = 'Links (' + [string]$links.Count + ')'; type = 'link'; sev = 'info'
                    detail = 'Navigation candidates parsed from HTML'
                    evidence = (Get-MaskedText ($linkSamples -join '; ') 220)
                    why = 'Links show the in-scope navigation surface. NetTruder did not follow them.'
                    fix = 'Keep authorisation checks server-side and replace javascript: URLs with reviewed controls.'
                    confidence = 'measured'; categories = @('web-xss-dom')
                })
            }
            if ($pathNodes.Count -gt 0) {
                $pathSamples = @($pathNodes | Select-Object -First 4 | ForEach-Object { ([string]$_.path) + ' HTTP ' + [string]$_.status })
                [void]$flowNodes.Add(@{
                    id = 'paths'; label = 'Exposed paths'; type = 'path'; sev = $(if ($exposureCount -gt 0) { 'high' } else { 'info' })
                    detail = ([string]$pathNodes.Count + ' known path(s) answered, ' + [string]$exposureCount + ' finding(s)')
                    evidence = (Get-MaskedText ($pathSamples -join '; ') 220)
                    why = 'These paths were requested with passive GET and returned a response; discovery alone is not exploitation.'
                    fix = 'Remove or protect exposed metadata, backups, admin surfaces and diagnostic endpoints.'
                    confidence = 'measured'; categories = @('web-exposure', 'web-directory', 'web-errors', 'web-comments')
                })
            }
            [void]$flowNodes.Add(@{
                id = 'data'; label = 'Data store'; type = 'data'; sev = 'info'
                detail = 'Inferred only; not visible passively'
                evidence = 'No database socket, query or credential was observed by this passive check.'
                why = 'Forms usually reach server-side storage, but the engine cannot confirm the product or topology.'
                confidence = 'inference'; categories = @()
            })
            [void]$flowNodes.Add(@{
                id = 'logs'; label = 'Logs / monitoring'; type = 'logs'; sev = $(if ($logCount -gt 0) { 'low' } else { 'info' })
                detail = ([string]$logCount + ' availability/contact finding(s)')
                evidence = ('security.txt status checked; error signatures scanned in the fetched body')
                why = 'Detective value depends on server-side logging and alerting that a passive client cannot see.'
                fix = 'Keep request/error logs, monitor 4xx/5xx spikes, and publish a monitored security contact.'
                confidence = 'partial inference'; categories = @('web-sec-txt', 'web-availability', 'web-errors')
            })

            [void]$flowEdges.Add(@{ from = 'browser'; to = 'tls'; label = 'request' })
            [void]$flowEdges.Add(@{ from = 'tls'; to = 'app'; label = 'response' })
            [void]$flowEdges.Add(@{ from = 'app'; to = 'headers'; label = 'headers' })
            if ($root.setcookie) { [void]$flowEdges.Add(@{ from = 'app'; to = 'cookies'; label = 'set-cookie' }) }
            if ($forms.Count -gt 0) { [void]$flowEdges.Add(@{ from = 'app'; to = 'forms'; label = 'forms' }) }
            if ($scripts.Count -gt 0) { [void]$flowEdges.Add(@{ from = 'app'; to = 'scripts'; label = 'loads' }) }
            if ($links.Count -gt 0) { [void]$flowEdges.Add(@{ from = 'app'; to = 'links'; label = 'links' }) }
            if ($pathNodes.Count -gt 0) { [void]$flowEdges.Add(@{ from = 'app'; to = 'paths'; label = 'probe' }) }
            [void]$flowEdges.Add(@{ from = 'app'; to = 'data'; label = 'read/write' })
            [void]$flowEdges.Add(@{ from = 'forms'; to = 'data'; label = 'queries' })
            [void]$flowEdges.Add(@{ from = 'app'; to = 'logs'; label = 'events' })

            Write-Evt 'webpage' 'info' '' @{
                url = $t.url
                status = $root.status
                answered = [bool]$root.ok
                ms = $root.ms
                title = $title
                length = $root.length
                scheme = $t.scheme
                host = $t.host
                port = $t.port
                server = (Get-WebHeader $h 'Server')
                powered = (Get-WebHeader $h 'X-Powered-By')
                score = $score
                grade = $grade
                https = ($t.scheme -eq 'https')
                tls = $tls
                missing = @(
                    $(if (-not $hsts) { 'HSTS' }), $(if (-not $csp) { 'CSP' }),
                    $(if (-not $xfo) { 'X-Frame-Options' }), $(if ($xcto -notmatch 'nosniff') { 'nosniff' }),
                    $(if (-not $ref) { 'Referrer-Policy' }), $(if (-not $perm) { 'Permissions-Policy' })
                )
                forms = @($forms)
                scripts = @($scripts)
                links = @($links | Select-Object -First 40)
                findings = $findings.Count
                high = @($findings | Where-Object { $_.sev -eq 'high' }).Count
                med = @($findings | Where-Object { $_.sev -eq 'med' }).Count
                low = @($findings | Where-Object { $_.sev -eq 'low' }).Count
                error = $root.error
            }
            Write-Evt 'webtree' 'info' '' @{ url = $t.url; nodes = @($treeNodes); edges = @($treeEdges) }
            Write-Evt 'webflow' 'info' '' @{ url = $t.url; nodes = $flowNodes; edges = $flowEdges }
            foreach ($f in $findings) { Write-Evt 'webfinding' 'warn' $f.title $f }
            $grandFindings += $findings.Count
            $grandScore += $score
            Write-Evt 'log' $(if ($findings.Count -gt 0) { 'warn' } else { 'ok' }) ('Web ' + $t.url + ' - ' + [string]$root.status + ' - grade ' + $grade + ' (' + [string]$findings.Count + ' finding(s))')
        }
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCallback
    }

    $avg = 0
    if ($targets.Count -gt 0) { $avg = [int]($grandScore / $targets.Count) }
    Write-Audit 'webscan' ('Web posture finished ({0} finding(s))' -f $grandFindings) @{ targets = $targets.Count }
    Write-Evt 'done' 'ok' ('Web posture finished - {0} target(s), {1} finding(s)' -f $targets.Count, $grandFindings) @{
        phase = 'webscan'; targets = $targets.Count; findings = $grandFindings
        score = $avg; zap = $zap.available; policy = $policy
    }
}

# ===========================================================================
# Code audit - static review of local source. Read-only; no code execution.
# ===========================================================================
# Build an evidence record for a source-only finding. This is deliberately a
# review lead with a safe checklist, never a claim of runtime exploitability.
function Get-CodeEvidence {
    param($Rule, [string]$Rel, [int]$Line, [string]$Snippet)
    $rid = [string]$Rule.id
    $cwe = [string]$Rule.cwe
    $why = [string]$Rule.why
    $research = [string]$Rule.research
    $evidence = 'Static match: {0} ({1}) at {2}:{3}. Masked line: {4}. No code was executed and no runtime path was exercised.' -f $rid, $cwe, $Rel, [string]$Line, $Snippet
    $reach = 'Review lead only: the pattern is present in a local file. Confirm the call chain and data flow in source before treating it as reachable.'
    $check = @(
        'Trace the value from its entry point to the flagged line using source review only.',
        'Confirm the safety condition in the documented fix is present on every path that reaches this line.',
        'Review compiler or runtime settings that change this behaviour without changing them in this tool.'
    )
    if ($research -eq 'kernel-source-review') {
        $reach = 'Static kernel review lead: no driver was built, signed, installed or loaded. Exploitability is not claimed; the checklist is the safe way to review the lead.'
        $check = @(
            'Read the surrounding function and name the caller of the flagged API.',
            'Verify destination capacity and source length checks before any copy or format call.',
            'Verify caller pointers are probed and copied into kernel memory before use.',
            'Confirm this driver is not built, signed, installed or loaded on this host.',
            'Record file:line and the documented fix. No exploit step is part of this tool.'
        )
    } else {
        $check += 'If further validation is needed, use an authorised isolated lab with no production data. This tool never runs payloads or exploit code.'
    }
    return @{
        evidence = $evidence
        reach = $reach
        preconditions = $why
        check = @($check)
        verdict = 'STATIC LEAD / NOT RUNTIME VERIFIED'
    }
}

function Get-CodeRuleSet {
    return @(
        @{ id = 'NT-CODE-001'; rx = '(?i)\b(innerHTML|outerHTML)\s*='; sev = 'med'; owasp = 'A03:2021 Injection'; cwe = 'CWE-79'; title = 'DOM HTML sink'; why = 'Assigning markup to innerHTML/outerHTML can execute attacker-controlled strings.'; fix = 'Use textContent, or sanitise with a maintained library (DOMPurify) and a strict CSP.'; research = 'web-xss-dom'; mask = $false }
        @{ id = 'NT-CODE-002'; rx = '(?i)document\.write\s*\('; sev = 'med'; owasp = 'A03:2021 Injection'; cwe = 'CWE-79'; title = 'document.write sink'; why = 'document.write can insert untrusted markup and break the parser.'; fix = 'Build nodes with createElement/textContent and append them.'; research = 'web-xss-dom'; mask = $false }
        @{ id = 'NT-CODE-003'; rx = '(?i)\beval\s*\(|new\s+Function\s*\('; sev = 'high'; owasp = 'A03:2021 Injection'; cwe = 'CWE-95'; title = 'Dynamic code evaluation'; why = 'eval/new Function execute strings as code and defeat CSP.'; fix = 'Replace with explicit data structures or a safe parser; remove unsafe-eval from CSP.'; research = 'web-code-eval'; mask = $false }
        @{ id = 'NT-CODE-004'; rx = '(?i)dangerouslySetInnerHTML'; sev = 'med'; owasp = 'A03:2021 Injection'; cwe = 'CWE-79'; title = 'React raw HTML sink'; why = 'dangerouslySetInnerHTML bypasses React escaping.'; fix = 'Sanitise the HTML with DOMPurify or render text/components instead.'; research = 'web-xss-dom'; mask = $false }
        @{ id = 'NT-CODE-005'; rx = '(?i)(select|insert|update|delete)\b[^\r\n]{0,160}(\+\s*[a-z_]|\$\{|%s|''\s*\+)'; sev = 'high'; owasp = 'A03:2021 Injection'; cwe = 'CWE-89'; title = 'Possible SQL string concatenation'; why = 'Building SQL from strings can allow injection when input is not parameterised.'; fix = 'Use parameterised queries/prepared statements. Never concatenate user input into SQL.'; research = 'web-sql-injection'; mask = $false }
        @{ id = 'NT-CODE-006'; rx = '(?i)(child_process|execSync|exec\(|spawn\(|system\(|popen\(|shell_exec|Runtime\.getRuntime\(\)\.exec)'; sev = 'high'; owasp = 'A03:2021 Injection'; cwe = 'CWE-78'; title = 'OS command execution'; why = 'Shell execution with untrusted input is command injection.'; fix = 'Use an argument-array API with a fixed binary, validate input against an allowlist, and drop the shell.'; research = 'web-command-injection'; mask = $false }
        @{ id = 'NT-CODE-007'; rx = '(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*["''][^"'']{6,}["'']'; sev = 'high'; owasp = 'A02:2021 Cryptographic Failures'; cwe = 'CWE-798'; title = 'Hard-coded credential or key'; why = 'Secrets in source are copied into builds, logs and backups.'; fix = 'Move the secret to a managed secret store, rotate it, and add the file to .gitignore.'; research = 'web-secrets'; mask = $true }
        @{ id = 'NT-CODE-008'; rx = 'BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY'; sev = 'high'; owasp = 'A02:2021 Cryptographic Failures'; cwe = 'CWE-321'; title = 'Private key material in tree'; why = 'Private keys in the repository allow impersonation if leaked.'; fix = 'Remove and rotate the key. Store keys in a hardware-backed or managed vault.'; research = 'web-secrets'; mask = $true }
        @{ id = 'NT-CODE-009'; rx = '(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|curl\s+-k)'; sev = 'high'; owasp = 'A02:2021 Cryptographic Failures'; cwe = 'CWE-295'; title = 'TLS certificate validation disabled'; why = 'Disabling validation removes the only defence against interception.'; fix = 'Enable validation and install the correct CA chain. Never ship verify=False.'; research = 'web-tls-https'; mask = $false }
        @{ id = 'NT-CODE-010'; rx = '(?i)access-control-allow-origin["'']?\s*[:=]\s*["'']\*'; sev = 'med'; owasp = 'A01:2021 Broken Access Control'; cwe = 'CWE-942'; title = 'CORS wildcard origin'; why = 'Any origin can read responses if credentials are also allowed.'; fix = 'Validate Origin against an allowlist; keep credentials off for public data.'; research = 'web-cors'; mask = $false }
        @{ id = 'NT-CODE-011'; rx = '(?i)http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|w3\.org|www\.gnu\.org|gnu\.org|www\.opensource\.org|opensource\.org|schemas\.|example\.com|xmlns)'; sev = 'low'; owasp = 'A02:2021 Cryptographic Failures'; cwe = 'CWE-319'; title = 'Cleartext HTTP endpoint'; why = 'HTTP endpoints expose content and tokens to the network.'; fix = 'Use HTTPS and redirect HTTP to HTTPS.'; research = 'web-tls-https'; mask = $false }
        @{ id = 'NT-CODE-012'; rx = '(?i)(md5|sha1)\s*\([^\r\n]*(password|passwd|secret|token)'; sev = 'med'; owasp = 'A02:2021 Cryptographic Failures'; cwe = 'CWE-328'; title = 'Weak hash used for a secret'; why = 'MD5/SHA1 are fast and unsuitable for password storage.'; fix = 'Use Argon2id, scrypt or bcrypt with a per-user salt and a work factor.'; research = 'web-crypto'; mask = $false }
        @{ id = 'NT-CODE-013'; rx = '(?i)Math\.random\(\)[^\r\n]{0,80}(token|session|password|nonce|secret)'; sev = 'med'; owasp = 'A02:2021 Cryptographic Failures'; cwe = 'CWE-338'; title = 'Non-cryptographic randomness for a secret'; why = 'Math.random is predictable and not suitable for tokens.'; fix = 'Use crypto.randomBytes / crypto.getRandomValues for security tokens.'; research = 'web-crypto'; mask = $false }
        @{ id = 'NT-CODE-014'; rx = '(?i)(yaml\.load\s*\(|pickle\.loads?\s*\(|unserialize\s*\()'; sev = 'high'; owasp = 'A08:2021 Software and Data Integrity Failures'; cwe = 'CWE-502'; title = 'Unsafe deserialisation'; why = 'Deserialising untrusted data can execute code.'; fix = 'Use safe_load / JSON, or a schema-validated format; never unpickle untrusted input.'; research = 'web-deserialisation'; mask = $false }
        @{ id = 'NT-CODE-015'; rx = '(?i)\bDEBUG\s*=\s*True|\bdebug\s*:\s*true'; sev = 'low'; owasp = 'A05:2021 Security Misconfiguration'; cwe = 'CWE-489'; title = 'Debug mode enabled'; why = 'Debug pages leak stack traces, settings and sometimes secrets.'; fix = 'Default debug to false and enable it only in a local, non-production environment.'; research = 'web-errors'; mask = $false }
        @{ id = 'NT-CODE-016'; rx = '(?i)(webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true|disable-web-security)'; sev = 'high'; owasp = 'A05:2021 Security Misconfiguration'; cwe = 'CWE-16'; title = 'Browser security disabled'; why = 'Disabling web security or allowing insecure content defeats the same-origin policy.'; fix = 'Remove the flag and fix the mixed-content or CORS cause.'; research = 'web-cors'; mask = $false }
        @{ id = 'NT-CODE-017'; rx = '(?i)unsafe-inline|unsafe-eval'; sev = 'low'; owasp = 'A05:2021 Security Misconfiguration'; cwe = 'CWE-693'; title = 'Weak CSP directive'; why = 'unsafe-inline/unsafe-eval weaken XSS protection.'; fix = 'Use nonces or hashes and remove unsafe directives.'; research = 'web-headers'; mask = $false }
        @{ id = 'NT-CODE-018'; rx = '(?i)alg["'']?\s*[:=]\s*["'']none|jwt\.decode\([^,)]*\)'; sev = 'high'; owasp = 'A07:2021 Identification and Authentication Failures'; cwe = 'CWE-347'; title = 'JWT signature not verified'; why = 'Accepting alg=none or decoding without verification allows token forgery.'; fix = 'Verify the signature, pin the algorithm, check iss/aud/exp and use a maintained JWT library.'; research = 'web-jwt'; mask = $false }
        @{ id = 'NT-CODE-019'; rx = '(?i)(readFile|sendFile|createReadStream|open|include|require)\s*\([^)]*(req\.|request\.|params|query)'; sev = 'high'; owasp = 'A01:2021 Broken Access Control'; cwe = 'CWE-22'; title = 'Possible path traversal'; why = 'User input used as a filesystem path can escape the intended directory.'; fix = 'Resolve against a fixed base, reject traversal, and allowlist filenames.'; research = 'web-path-traversal'; mask = $false }
        @{ id = 'NT-CODE-020'; rx = '(?i)(exec|eval)\s*\([^)]*(req\.|request\.|params|query)'; sev = 'high'; owasp = 'A03:2021 Injection'; cwe = 'CWE-95'; title = 'User input reaches code execution'; why = 'Request data used in eval/exec is direct code injection.'; fix = 'Remove dynamic execution; map input to a fixed action table.'; research = 'web-code-eval'; mask = $false }
        @{ id = 'NT-CODE-021'; rx = '(?i)localStorage\.(setItem|getItem)[^\r\n]{0,80}(token|password|secret|jwt)'; sev = 'med'; owasp = 'A02:2021 Cryptographic Failures'; cwe = 'CWE-922'; title = 'Secret stored in browser storage'; why = 'localStorage is readable by any script on the origin and does not expire.'; fix = 'Use an HttpOnly, Secure, SameSite cookie for session state; keep tokens out of storage.'; research = 'web-cookies'; mask = $false }
        @{ id = 'NT-CODE-022'; rx = '(?i)console\.(log|debug|info)[^\r\n]{0,80}(password|secret|token|api[_-]?key)'; sev = 'med'; owasp = 'A09:2021 Security Logging and Monitoring Failures'; cwe = 'CWE-532'; title = 'Secret written to logs'; why = 'Logs are widely readable and often exported.'; fix = 'Remove the secret from the log call and redact it at the logger.'; research = 'web-logging'; mask = $true }
        @{ id = 'NT-CODE-023'; rx = '(?i)postMessage\s*\([^)]*,\s*["'']\*["'']'; sev = 'low'; owasp = 'A01:2021 Broken Access Control'; cwe = 'CWE-345'; title = 'postMessage to any origin'; why = 'Any embedding or opener can receive the message.'; fix = 'Send to a specific target origin and validate event.origin on receipt.'; research = 'web-cors'; mask = $false }
        @{ id = 'NT-CODE-024'; rx = '(?i)target\s*=\s*["'']_blank["''][^>]*(?!rel\s*=\s*["''][^"'']*noopener)'; sev = 'low'; owasp = 'A05:2021 Security Misconfiguration'; cwe = 'CWE-1022'; title = 'target=_blank without noopener'; why = 'The opened page can access window.opener in some browsers.'; fix = 'Add rel="noopener noreferrer" to external links opened in a new tab.'; research = 'web-headers'; mask = $false }
        @{ id = 'NT-CODE-025'; rx = '(?i)(TODO|FIXME)[^\r\n]{0,80}(auth|security|sanit|escape|permission|access)'; sev = 'info'; owasp = 'A04:2021 Insecure Design'; cwe = 'CWE-1059'; title = 'Security TODO/FIXME'; why = 'Unfinished security work tends to ship.'; fix = 'Track it as a security ticket with an owner and a due date; do not merge the branch until it is resolved.'; research = 'web-design'; mask = $false }
        @{ id = 'NT-CODE-026'; rx = '(?i)(Access-Control-Allow-Credentials["'']?\s*[:=]\s*["'']?true)'; sev = 'low'; owasp = 'A01:2021 Broken Access Control'; cwe = 'CWE-942'; title = 'CORS credentials enabled'; why = 'Credentials plus a permissive origin allow attacker reads.'; fix = 'Keep credentials off unless required, and allowlist exact origins.'; research = 'web-cors'; mask = $false }
        @{ id = 'NT-CODE-027'; rx = '(?i)(window\.open|location\.href)\s*=\s*[^;]*(req\.|request\.|params|query)'; sev = 'med'; owasp = 'A01:2021 Broken Access Control'; cwe = 'CWE-601'; title = 'Possible open redirect'; why = 'Redirecting to user input enables phishing and token leaks.'; fix = 'Allowlist destinations or use an opaque server-side mapping.'; research = 'web-redirect'; mask = $false }
        @{ id = 'NT-CODE-028'; rx = '(?i)(trust\s+proxy|X-Forwarded-For)[^\r\n]{0,80}(true|always)'; sev = 'low'; owasp = 'A04:2021 Insecure Design'; cwe = 'CWE-348'; title = 'Spoofable forwarded header'; why = 'Trusting client-supplied forwarded headers breaks rate limits and audit logs.'; fix = 'Trust only a known proxy chain and strip client-supplied headers at the edge.'; research = 'web-design'; mask = $false }
        # Defensive kernel/source-review rules. These flag review subjects, not
        # confirmed vulnerabilities. They are used by the static HEVD study lab.
        @{ id = 'NT-C-DANGEROUS-COPY'; rx = '(?i)\b(memcpy|memmove|RtlCopyMemory|RtlMoveMemory|strcpy|strcat|sprintf|wsprintf|swprintf|wcscpy)\s*\('; sev = 'high'; owasp = 'A03:2021 Injection'; cwe = 'CWE-120'; title = 'Kernel copy or format API review'; why = 'Unbounded copy and format calls need a verified destination capacity and source length before use.'; fix = 'Use a bounded helper with an explicit destination size, validate caller lengths, and check arithmetic before the copy.'; research = 'kernel-source-review'; mask = $false }
        @{ id = 'NT-C-POOL-ALLOC'; rx = '(?i)\b(ExAllocatePool|ExAllocatePoolWithTag|ExAllocatePool2|ExAllocatePool3|ExFreePool|ExFreePoolWithTag)\s*\('; sev = 'med'; owasp = 'A04:2021 Insecure Design'; cwe = 'CWE-789'; title = 'Kernel pool allocation review'; why = 'Pool size arithmetic, initialisation and free paths must be checked to avoid undersized or dangling allocations.'; fix = 'Use checked arithmetic for sizes, initialise allocations, and clear pointers after free with a single owner.'; research = 'kernel-source-review'; mask = $false }
        @{ id = 'NT-C-IOCTL-DISPATCH'; rx = '(?i)(IRP_MJ_DEVICE_CONTROL|DeviceIoControl|IoControlCode|InputBufferLength|OutputBufferLength)'; sev = 'med'; owasp = 'A01:2021 Broken Access Control'; cwe = 'CWE-862'; title = 'Device-control boundary review'; why = 'Device-control handlers need explicit input and output length checks and scoped access before buffers are used.'; fix = 'Validate both lengths, use a fixed buffer method with a documented range, and scope device access to the accounts that need it.'; research = 'kernel-source-review'; mask = $false }
        @{ id = 'NT-C-USER-POINTER'; rx = '(?i)\b(ProbeForRead|ProbeForWrite|MmUserProbeAddress)\s*\('; sev = 'med'; owasp = 'A01:2021 Broken Access Control'; cwe = 'CWE-822'; title = 'User-pointer boundary review'; why = 'Caller-supplied pointers must be probed and copied once into kernel-owned memory before validation and use.'; fix = 'Probe the buffer, copy it into kernel memory once inside exception handling, then validate and use only the copy.'; research = 'kernel-source-review'; mask = $false }
        @{ id = 'NT-C-INIT'; rx = '(?i)\b(RtlZeroMemory|ZeroMemory|=\s*\{\s*0\s*\})'; sev = 'info'; owasp = 'A04:2021 Insecure Design'; cwe = 'CWE-457'; title = 'Buffer initialisation review'; why = 'Confirm that a structure is initialised before it is copied or returned to a caller.'; fix = 'Zero or explicitly initialise the whole structure before populating fields and enable compiler warnings for uninitialised use.'; research = 'kernel-source-review'; mask = $false }
        @{ id = 'NT-C-INT-WRAP'; rx = '(?i)\b(size|length|len|count|bytes|total|alloc|terminator|offset|index|elements|num)[a-z0-9_]*\s*[+*]\s*[A-Za-z_][A-Za-z0-9_]*\s*[)>]'; sev = 'med'; owasp = 'A04:2021 Insecure Design'; cwe = 'CWE-190'; title = 'Integer size arithmetic in a bound check'; why = 'Size arithmetic inside a bound check can wrap a fixed-width value, so the comparison reads a smaller number than the real requirement.'; fix = 'Use checked arithmetic, reject sizes above a documented maximum, and verify the bound after the calculation with a consistent wide type.'; research = 'kernel-source-review'; mask = $false }
        @{ id = 'NT-C-CUSTOM'; rx = '(?i)\bNT[-_]C[-_]CUSTOM\b'; sev = 'info'; owasp = 'A04:2021 Insecure Design'; cwe = 'CWE-1059'; title = 'Custom kernel review marker'; why = 'Placeholder for a narrow, locally authored defensive rule. Read the surrounding source before recording a finding.'; fix = 'Replace this marker with one narrow rule per bug class; keep the reason and fix explicit so results stay explainable.'; research = 'kernel-source-review'; mask = $false }
    )
}

function Invoke-CodeAudit {
    $root = $Path
    if ([string]::IsNullOrWhiteSpace($root)) { $root = Split-Path -Parent $script:EngineDir }
    if (-not (Test-Path -LiteralPath $root)) {
        Write-Evt 'log' 'err' ('Code path not found: ' + $root)
        Write-Evt 'done' 'err' 'Code audit had no readable path.' @{ phase = 'codeaudit'; path = $root }
        return
    }
    try { $root = (Resolve-Path -LiteralPath $root).Path } catch { }
    $exts = @('.js', '.jsx', '.ts', '.tsx', '.html', '.htm', '.hta', '.py', '.php', '.rb', '.java', '.cs', '.go', '.ps1', '.json', '.yml', '.yaml', '.xml', '.config', '.env', '.ini', '.md', '.txt', '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx')
    $skip = '\\(node_modules|\.git|bin|obj|dist|build|vendor|runs|lab|state|audit|logs|\.venv|venv|__pycache__|\.next|coverage|\.cache)\\'
    $maxFiles = 1500
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $exts -contains $_.Extension.ToLower() -and
            $_.FullName -notmatch $skip -and
            $_.Length -lt 1048576 -and
            $_.FullName -ne $PSCommandPath
        } | Sort-Object FullName)
    $truncated = $false
    if ($files.Count -gt $maxFiles) { $files = @($files | Select-Object -First $maxFiles); $truncated = $true }

    $rules = Get-CodeRuleSet
    $findings = New-Object System.Collections.ArrayList
    $seen = @{}
    $scanned = 0
    $skipped = 0
    $languages = @{}
    $fileRows = New-Object System.Collections.ArrayList
    $limitHit = $false

    Write-Audit 'codeaudit' ('Static code review ({0} file(s))' -f $files.Count) @{ path = $root }
    Write-Evt 'log' 'ok' ('Code audit start - ' + $root + ' (' + [string]$files.Count + ' file(s))')

    foreach ($f in $files) {
        if ($limitHit) { break }
        $lang = 'other'
        switch ($f.Extension.ToLower()) {
            '.js' { $lang = 'javascript' } '.jsx' { $lang = 'javascript' } '.ts' { $lang = 'typescript' } '.tsx' { $lang = 'typescript' }
            '.html' { $lang = 'html' } '.htm' { $lang = 'html' } '.hta' { $lang = 'html' }
            '.py' { $lang = 'python' } '.php' { $lang = 'php' } '.rb' { $lang = 'ruby' } '.java' { $lang = 'java' }
            '.cs' { $lang = 'csharp' } '.go' { $lang = 'go' } '.ps1' { $lang = 'powershell' }
            '.json' { $lang = 'json' } '.yml' { $lang = 'yaml' } '.yaml' { $lang = 'yaml' } '.xml' { $lang = 'xml' }
            '.config' { $lang = 'config' } '.env' { $lang = 'env' } '.ini' { $lang = 'ini' } '.md' { $lang = 'markdown' } '.txt' { $lang = 'text' }
            '.c' { $lang = 'c' } '.h' { $lang = 'c' }
            '.cpp' { $lang = 'cpp' } '.hpp' { $lang = 'cpp' } '.cc' { $lang = 'cpp' } '.cxx' { $lang = 'cpp' }
        }
        if (-not $languages.ContainsKey($lang)) { $languages[$lang] = 0 }
        $languages[$lang]++

        $rel = $f.FullName.Substring($root.Length).TrimStart('\')
        $secretFile = [bool]($f.Name -match '(?i)^(\.env|id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.(pem|pfx|p12|kdbx|key)|credentials.*|secrets.*)$')
        $fileFindings = 0
        $fileHits = New-Object System.Collections.ArrayList
        if ($secretFile) {
            $key = 'NT-CODE-FILE|' + $rel
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $evRow = Get-CodeEvidence -Rule @{ id = 'NT-CODE-FILE'; cwe = 'CWE-538'; why = 'A credential or key file is stored inside the project tree.'; research = 'web-secrets' } -Rel $rel -Line 1 -Snippet (Get-MaskedText $f.Name 120)
                [void]$findings.Add(@{
                    id = 'NT-CODE-FILE'; rule = 'secret-file'; file = $rel; line = 1; sev = 'high'
                    title = 'Secret/credential file in tree'; owasp = 'A02:2021 Cryptographic Failures'; cwe = 'CWE-538'
                    why = 'A credential or key file is stored inside the project tree.'; fix = 'Remove it, rotate the material, and use a secret manager or an OS-protected store.'
                    research = 'web-secrets'; snippet = $f.Name; confidence = 'high'
                    evidence = $evRow.evidence; reach = $evRow.reach; preconditions = $evRow.preconditions
                    check = $evRow.check; verdict = $evRow.verdict
                })
                $fileFindings++
                [void]$fileHits.Add(@{ line = 1; id = 'NT-CODE-FILE'; sev = 'high'; title = 'Secret/credential file in tree' })
            }
        }

        $lines = $null
        try { $lines = [System.IO.File]::ReadAllLines($f.FullName) } catch { $skipped++; continue }
        $scanned++
        $lineCount = [Math]::Min($lines.Count, 5000)
        for ($i = 0; $i -lt $lineCount; $i++) {
            $line = [string]$lines[$i]
            if ($line.Length -eq 0) { continue }
            foreach ($r in $rules) {
                if (-not [regex]::IsMatch($line, $r.rx)) { continue }
                $key = $r.id + '|' + $rel + '|' + [string]($i + 1)
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $snip = Get-MaskedText $line.Trim() 240
                if ($r.mask) {
                    $snip = $snip -replace '(?i)([:=]\s*["''])[^"'']{6,}(["''])', '$1***$2'
                }
                $evRow = Get-CodeEvidence -Rule $r -Rel $rel -Line ($i + 1) -Snippet $snip
                [void]$findings.Add(@{
                    id = $r.id; rule = $r.id; file = $rel; line = ($i + 1); sev = $r.sev
                    title = $r.title; owasp = $r.owasp; cwe = $r.cwe; why = $r.why
                    fix = $r.fix; research = $r.research; snippet = $snip; confidence = 'medium'
                    evidence = $evRow.evidence; reach = $evRow.reach; preconditions = $evRow.preconditions
                    check = $evRow.check; verdict = $evRow.verdict
                })
                [void]$fileHits.Add(@{ line = ($i + 1); id = $r.id; sev = $r.sev; title = $r.title })
                $fileFindings++
                if ($findings.Count -ge 250) { $limitHit = $true; break }
            }
            if ($limitHit) { break }
        }
        $contentLines = New-Object System.Collections.ArrayList
        $contentLimit = 4000
        if (-not $secretFile) {
            $contentEnd = [Math]::Min($lines.Count, $contentLimit)
            for ($li = 0; $li -lt $contentEnd; $li++) {
                [void]$contentLines.Add((Get-MaskedText ([string]$lines[$li]) 800))
            }
        }
        if ($fileFindings -gt 0) {
            [void]$fileRows.Add(@{
                path = $rel; lang = $lang; lines = $lines.Count; findings = $fileFindings
                hits = @($fileHits); content = @($contentLines)
                contentWithheld = $secretFile
                contentTruncated = ($lines.Count -gt $contentLimit)
                contentLines = $contentLines.Count
            })
        }
        if ($findings.Count -ge 250) { $limitHit = $true }
    }

    $bySev = @{ high = 0; med = 0; low = 0; info = 0 }
    foreach ($x in $findings) { if ($bySev.ContainsKey($x.sev)) { $bySev[$x.sev]++ } }
    $langRows = @()
    foreach ($k in $languages.Keys) { $langRows += @{ name = $k; count = $languages[$k] } }

    Write-Evt 'codemeta' 'info' '' @{
        path = $root
        files = $files.Count
        scanned = $scanned
        skipped = $skipped
        truncated = $truncated
        limitHit = $limitHit
        rules = $rules.Count
        findings = $findings.Count
        high = $bySev.high
        med = $bySev.med
        low = $bySev.low
        info = $bySev.info
        languages = @($langRows)
        policy = 'Static, read-only review of local files. No source is executed, no dependency is installed, and no secret value is printed in full.'
    }
    foreach ($fr in @($fileRows | Sort-Object { $_.findings } -Descending | Select-Object -First 120)) {
        Write-Evt 'codefile' 'info' '' $fr
    }
    foreach ($x in ($findings | Sort-Object { $_.sev })) {
        Write-Evt 'codefinding' 'warn' $x.title $x
    }
    Write-Evt 'log' $(if ($findings.Count -gt 0) { 'warn' } else { 'ok' }) ('Code audit - ' + [string]$scanned + ' file(s), ' + [string]$findings.Count + ' finding(s), ' + [string]$bySev.high + ' high')
    Write-Audit 'codeaudit' ('Static review finished ({0} finding(s))' -f $findings.Count) @{ path = $root; scanned = $scanned }
    Write-Evt 'done' 'ok' ('Code audit finished - ' + [string]$findings.Count + ' finding(s)') @{
        phase = 'codeaudit'; path = $root; files = $files.Count; scanned = $scanned
        findings = $findings.Count; high = $bySev.high; med = $bySev.med; low = $bySev.low; info = $bySev.info
    }
}

# ===========================================================================
# Opt-in source editing. Disabled in the UI by default; the engine still
# validates the audited root, requires explicit acknowledgement, and backs up
# the original file before any write.
# ===========================================================================
function Resolve-CodeTarget {
    param([string]$Root, [string]$Relative)
    if ([string]::IsNullOrWhiteSpace($Root) -or [string]::IsNullOrWhiteSpace($Relative)) { return $null }
    try { $rootFull = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).Path } catch { return $null }
    $rel = [string]$Relative
    if ($rel -match '[\x00-\x1f]') { return $null }
    $rel = $rel -replace '/', '\'
    $parts = @($rel -split '\\')
    if ([IO.Path]::IsPathRooted($rel) -or ($parts -contains '..')) { return $null }
    $full = [IO.Path]::GetFullPath((Join-Path $rootFull $rel))
    $prefix = $rootFull.TrimEnd('\') + '\'
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return $null }
    return @{ Full = $full; Rel = $rel; Root = $rootFull }
}

function Get-CodeEncoding {
    param([byte[]]$Bytes)
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        return @{ Name = 'utf-8-bom'; Encoding = (New-Object Text.UTF8Encoding($true, $false)) }
    }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
        return @{ Name = 'utf-16le'; Encoding = [Text.Encoding]::Unicode }
    }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
        return @{ Name = 'utf-16be'; Encoding = [Text.Encoding]::BigEndianUnicode }
    }
    return @{ Name = 'utf-8'; Encoding = (New-Object Text.UTF8Encoding($false, $false)) }
}

function Get-CodeEol {
    param([string]$Text)
    if ($Text.IndexOf("`r`n") -ge 0) { return 'crlf' }
    return 'lf'
}

function Invoke-CodeRead {
    if (-not $Yes) {
        Write-Evt 'log' 'err' 'Raw source read needs explicit confirmation.'
        Write-Evt 'done' 'err' 'Raw source read refused.' @{ phase = 'coderead' }
        return
    }
    $target = Resolve-CodeTarget $Path $ItemId
    if (-not $target) {
        Write-Evt 'log' 'err' ('Refused source read outside the audited root: ' + [string]$ItemId)
        Write-Evt 'done' 'err' 'Source read refused by path guard.' @{ phase = 'coderead'; path = [string]$ItemId }
        return
    }
    try {
        $bytes = [IO.File]::ReadAllBytes($target.Full)
        if ($bytes.Length -gt 1048576) {
            Write-Evt 'log' 'err' 'Source read refused: file is larger than 1 MB.'
            Write-Evt 'done' 'err' 'Source read refused by size guard.' @{ phase = 'coderead'; path = $target.Rel }
            return
        }
        $encInfo = Get-CodeEncoding $bytes
        $text = $encInfo.Encoding.GetString($bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
        $eol = Get-CodeEol $text
        $lines = @($text -split "\r?\n")
        Write-Evt 'coderaw' 'info' ('Raw source opened for review: ' + $target.Rel) @{
            path = $target.Rel; root = $target.Root; lines = $lines.Count
            encoding = $encInfo.Name; eol = $eol; content = @($lines)
        }
        Write-Audit 'coderead' ('Raw source opened: ' + $target.Rel) @{ path = $target.Rel; root = $target.Root }
        Write-Evt 'done' 'ok' ('Raw source loaded - ' + [string]$lines.Count + ' line(s)') @{
            phase = 'coderead'; path = $target.Rel; lines = $lines.Count; encoding = $encInfo.Name; eol = $eol
        }
    } catch {
        Write-Evt 'log' 'err' ('Source read failed: ' + $_.Exception.Message)
        Write-Evt 'done' 'err' 'Source read failed.' @{ phase = 'coderead'; path = $target.Rel }
    }
}

function Invoke-CodeWrite {
    if (-not $Yes -or -not $AckRisk) {
        Write-Evt 'log' 'err' 'Source write needs both explicit confirmation and risk acknowledgement.'
        Write-Evt 'done' 'err' 'Source write refused.' @{ phase = 'codewrite' }
        return
    }
    $target = Resolve-CodeTarget $Path $ItemId
    if (-not $target) {
        Write-Evt 'log' 'err' ('Refused source write outside the audited root: ' + [string]$ItemId)
        Write-Evt 'done' 'err' 'Source write refused by path guard.' @{ phase = 'codewrite'; path = [string]$ItemId }
        return
    }
    if ([string]::IsNullOrWhiteSpace($ContentFile) -or -not (Test-Path -LiteralPath $ContentFile -PathType Leaf)) {
        Write-Evt 'log' 'err' 'Source write refused: content file is missing.'
        Write-Evt 'done' 'err' 'Source write refused.' @{ phase = 'codewrite'; path = $target.Rel }
        return
    }
    try { $contentFull = (Resolve-Path -LiteralPath $ContentFile -ErrorAction Stop).Path } catch {
        Write-Evt 'log' 'err' 'Source write refused: content file could not be resolved.'
        Write-Evt 'done' 'err' 'Source write refused.' @{ phase = 'codewrite'; path = $target.Rel }
        return
    }
    $dataPrefix = $script:Root.TrimEnd('\') + '\'
    if (-not $contentFull.StartsWith($dataPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Evt 'log' 'err' 'Source write refused: content file is outside the NetTruder data root.'
        Write-Evt 'done' 'err' 'Source write refused by content guard.' @{ phase = 'codewrite'; path = $target.Rel }
        return
    }
    try {
        $text = [IO.File]::ReadAllText($contentFull, [Text.Encoding]::Unicode)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
        if ($text.Length -gt 2000000) {
            Write-Evt 'log' 'err' 'Source write refused: content is larger than 2 million characters.'
            Write-Evt 'done' 'err' 'Source write refused by size guard.' @{ phase = 'codewrite'; path = $target.Rel }
            return
        }
        $original = [IO.File]::ReadAllBytes($target.Full)
        $encInfo = Get-CodeEncoding $original
        $originalText = $encInfo.Encoding.GetString($original)
        $eol = Get-CodeEol $originalText
        if ($eol -eq 'crlf') {
            $text = ($text -replace "`r`n", "`n") -replace "`n", "`r`n"
        } else {
            $text = $text -replace "`r`n", "`n"
        }
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
        $backupDir = Join-Path $script:State ('code-edits\' + $stamp)
        $backupFile = Join-Path $backupDir $target.Rel
        $backupParent = Split-Path -Parent $backupFile
        if (-not (Test-Path -LiteralPath $backupParent)) { New-Item -ItemType Directory -Path $backupParent -Force | Out-Null }
        [IO.File]::WriteAllBytes($backupFile, $original)
        [IO.File]::WriteAllText($target.Full, $text, $encInfo.Encoding)
        $manifest = @{
            at = (Get-Date).ToUniversalTime().ToString('o'); runId = $RunId
            root = $target.Root; path = $target.Rel; backup = $backupFile
            encoding = $encInfo.Name; eol = $eol; originalBytes = $original.Length
            writtenChars = $text.Length
        } | ConvertTo-Json -Depth 6
        [IO.File]::WriteAllText((Join-Path $backupDir 'manifest.json'), $manifest, (New-Object Text.UTF8Encoding($false, $false)))
        Write-Evt 'codewrite' 'ok' ('Source saved with backup: ' + $target.Rel) @{
            path = $target.Rel; root = $target.Root; backup = $backupFile
            encoding = $encInfo.Name; eol = $eol; writtenChars = $text.Length
        }
        Write-Audit 'codewrite' ('Source saved: ' + $target.Rel) @{ path = $target.Rel; backup = $backupFile }
        Write-Evt 'done' 'ok' ('Source saved - ' + $target.Rel) @{
            phase = 'codewrite'; path = $target.Rel; backup = $backupFile; eol = $eol
        }
    } catch {
        Write-Evt 'log' 'err' ('Source write failed: ' + $_.Exception.Message)
        Write-Evt 'done' 'err' 'Source write failed.' @{ phase = 'codewrite'; path = $target.Rel }
    }
}

# ===========================================================================
# Snapshot persistence - every analysis pass keeps a JSON copy under state.
# ===========================================================================
function Save-Snapshot {
    param([string]$Kind, $Data)
    $dir = Join-Path $script:State 'snapshots'
    try {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $file = Join-Path $dir ('{0}-{1}.json' -f $Kind, (Get-Date).ToString('yyyyMMdd-HHmmss'))
        $json = ConvertTo-Json -InputObject $Data -Depth 12
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($file, $json, $enc)
        $all = @(Get-ChildItem -LiteralPath $dir -Filter ($Kind + '-*.json') -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($all.Count -gt 20) {
            foreach ($old in @($all | Select-Object -Skip 20)) {
                Remove-Item -LiteralPath $old.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        return $file
    } catch { return '' }
}

# ===========================================================================
# Flow - process tree plus process-to-endpoint data flow. Read-only.
# ===========================================================================
function Get-FlowSensitivity {
    param([string]$Name, [string]$Path, [string]$Cmd)
    $n = ([string]$Name).ToLower()
    $p = [string]$Path
    $notes = @()
    $sev = 'info'
    $scriptHosts = @('powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'msbuild', 'installutil', 'certutil', 'bitsadmin', 'wmic', 'psexec', 'psexesvc', 'netcat', 'nc', 'ncat')
    if ($scriptHosts -contains $n) { $notes += 'script or proxy-execution host'; $sev = 'med' }
    if ($p -match '(?i)\\(temp|tmp|downloads|public|programdata)\\|\\appdata\\local\\temp\\') { $notes += 'image in a user-writable path'; $sev = 'high' }
    if ($p -match '(?i)\.(js|jse|vbs|vbe|wsf|hta|ps1|bat|cmd|scr|pif)$') { $notes += 'script/image extension'; $sev = 'high' }
    if ($Cmd -match '(?i)(-enc |-encodedcommand|frombase64string|downloadstring|invoke-expression|iex \(|hidden)') { $notes += 'encoded or hidden command line'; $sev = 'high' }
    return @{ sev = $sev; notes = $notes }
}

function Invoke-Flow {
    param([int]$Limit = 240)
    Write-Audit 'flow' 'Process tree and data-flow map' @{ limit = $Limit }
    Write-Evt 'log' 'dim' 'Collecting process tree, owners and TCP flow (read-only).'

    $ownerMap = @{}
    $procRows = @()
    $source = 'cim'
    try {
        $cim = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $ids = @($cim | ForEach-Object { [int]$_.ProcessId })
        $ownerMap = Get-OwnerMap -Ids $ids
        foreach ($cp in $cim) {
            $cmd = [string]$cp.CommandLine
            if ($cmd.Length -gt 300) { $cmd = $cmd.Substring(0, 300) + '...' }
            $procRows += [pscustomobject]@{
                pid = [int]$cp.ProcessId; ppid = [int]$cp.ParentProcessId
                name = [string]$cp.Name; path = [string]$cp.ExecutablePath
                cmd = $cmd; owner = ''
            }
        }
    } catch {
        $source = 'process'
        try {
            foreach ($p in @(Get-Process -ErrorAction Stop)) {
                $procRows += [pscustomobject]@{
                    pid = [int]$p.Id; ppid = 0; name = [string]$p.ProcessName
                    path = ''; cmd = ''; owner = ''
                }
            }
            $ownerMap = Get-OwnerMap -Ids @($procRows | ForEach-Object { [int]$_.pid })
        } catch { }
    }
    foreach ($r in $procRows) {
        if ($ownerMap.ContainsKey([int]$r.pid)) { $r.owner = [string]$ownerMap[[int]$r.pid] }
    }

    $conns = @()
    try { $conns = @(Get-NetTCPConnection -ErrorAction Stop) } catch { }

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList
    $findings = New-Object System.Collections.ArrayList
    $seenFind = @{}
    $byPid = @{}
    $endpointCount = @{}
    foreach ($c in $conns) {
        if ([string]$c.State -eq 'Listen') { continue }
        $op = [int]$c.OwningProcess
        if ($op -le 0) { continue }
        if (-not $endpointCount.ContainsKey($op)) { $endpointCount[$op] = 0 }
        $endpointCount[$op]++
    }

    $order = @($procRows | Sort-Object { [int]$_.pid })
    if ($order.Count -gt $Limit) { $order = @($order | Select-Object -First $Limit) }
    $present = @{}
    foreach ($r in $order) { $present[[int]$r.pid] = $true }

    foreach ($r in $order) {
        $sens = Get-FlowSensitivity -Name $r.name -Path $r.path -Cmd $r.cmd
        $nid = 'p' + [string]$r.pid
        $byPid[[int]$r.pid] = $nid
        [void]$nodes.Add(@{
            id = $nid; label = $r.name; type = 'process'; sev = $sens.sev
            pid = [int]$r.pid; ppid = [int]$r.ppid; owner = $r.owner; path = $r.path
            cmd = $r.cmd; conns = [int]$endpointCount[[int]$r.pid]
            detail = (($sens.notes) -join '; ')
        })
    }
    foreach ($r in $order) {
        $pp = [int]$r.ppid
        if ($pp -le 0 -or $pp -eq [int]$r.pid) { continue }
        if ($present.ContainsKey($pp) -and $byPid.ContainsKey($pp)) {
            [void]$edges.Add(@{ from = $byPid[$pp]; to = $byPid[[int]$r.pid]; label = 'spawn' })
        }
    }

    $endpoints = @{}
    foreach ($c in $conns) {
        $state = [string]$c.State
        if ($state -eq 'Listen') { continue }
        $op = [int]$c.OwningProcess
        if ($op -le 0 -or -not $byPid.ContainsKey($op)) { continue }
        $remote = [string]$c.RemoteAddress
        $rport = [int]$c.RemotePort
        if (-not $remote -or $remote -eq '0.0.0.0' -or $remote -eq '::') { continue }
        $key = $remote + ':' + [string]$rport
        if (-not $endpoints.ContainsKey($key)) {
            $private = Test-PrivateIp $remote
            $svc = Get-ServiceName $rport
            if (-not $svc) { $svc = 'tcp/' + [string]$rport }
            $lsev = 'info'
            if (-not $private) { $lsev = 'low' }
            if ($rport -in @(4444, 5555, 6666, 1337, 31337, 9001, 1080, 1081)) { $lsev = 'high' }
            if ($rport -in @(445, 135, 3389, 5985, 5986, 22, 23, 5900)) { $lsev = 'med' }
            $endpoints[$key] = @{
                id = 'e' + [string]([Math]::Abs($key.GetHashCode()))
                label = $key; type = 'remote'; sev = $lsev
                detail = ($(if ($private) { 'private' } else { 'public' }) + ' / ' + $svc + ' / ' + $state)
                remote = $remote; port = $rport; private = $private
            }
            [void]$nodes.Add($endpoints[$key])
        }
        $nid = $endpoints[$key].id
        $src = $byPid[$op]
        $dup = $false
        foreach ($e in $edges) {
            if ($e.from -eq $src -and $e.to -eq $nid) { $dup = $true; break }
        }
        if (-not $dup) { [void]$edges.Add(@{ from = $src; to = $nid; label = $state }) }
    }

    $add = {
        param($id, $sev, $title, $detail, $fix, $research)
        if ($seenFind.ContainsKey($id)) { return }
        $seenFind[$id] = $true
        [void]$findings.Add(@{
            id = $id; sev = $sev; title = $title; detail = $detail
            fix = $fix; research = $research
        })
    }

    foreach ($r in $order) {
        $op = [int]$r.pid
        $rc = 0
        if ($endpointCount.ContainsKey($op)) { $rc = [int]$endpointCount[$op] }
        if ($rc -le 0) { continue }
        $low = ([string]$r.name).ToLower()
        $sens = Get-FlowSensitivity -Name $r.name -Path $r.path -Cmd $r.cmd
        $hasPublic = $false
        foreach ($c in $conns) {
            if ([int]$c.OwningProcess -ne $op) { continue }
            if ([string]$c.State -eq 'Listen') { continue }
            if (-not (Test-PrivateIp ([string]$c.RemoteAddress))) { $hasPublic = $true; break }
        }
        if ($sens.sev -eq 'high') {
            & $add ('FLOW-SENS-' + [string]$op) 'high' ('Sensitive image with network activity: ' + $r.name) ($r.path + ' - ' + (($sens.notes) -join '; ')) 'Review the parent process, the user, and the command line. If this was not an approved test, end the process, preserve the command line, and check what it contacted.' 'process-tree'
        }
        if ($rc -ge 13) {
            & $add ('FLOW-FANOUT-' + [string]$op) 'med' ('Many concurrent flows: ' + $r.name + ' (' + [string]$rc + ')') ($r.path + ' owner ' + $r.owner) 'Confirm the process is an approved browser, updater or agent. A normal desktop app rarely holds a dozen simultaneous remote flows.' 'lateral-movement'
        }
        if ($hasPublic -and $low -in @('powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin')) {
            & $add ('FLOW-LOL-' + [string]$op) 'high' ('Script host with public egress: ' + $r.name) ($r.cmd) 'Capture the full command line and remote address. Block the destination at the egress firewall and review the script that made the call.' 'egress-monitoring'
        }
        $company = ''
        if ($r.path -and (Test-Path -LiteralPath $r.path)) {
            try { $company = [string]([System.Diagnostics.FileVersionInfo]::GetVersionInfo($r.path).CompanyName) } catch { }
        }
        if ($hasPublic -and $r.path -and -not $company -and $r.path -notmatch '(?i)^[a-z]:\\windows\\' -and $sens.sev -ne 'high') {
            & $add ('FLOW-NOPUB-' + [string]$op) 'low' ('Process with public egress and no publisher metadata: ' + $r.name) ($r.path + ' pid ' + [string]$op) 'Confirm the binary is approved and comes from a managed install path. A missing CompanyName is a review trigger, not proof of malice.' 'software-integrity'
        }
    }

    foreach ($l in @($conns | Where-Object { [string]$_.State -eq 'Listen' })) {
        $lp = [int]$l.LocalPort
        if ($lp -notin @(21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017)) { continue }
        $op = [int]$l.OwningProcess
        $nm = 'pid ' + [string]$op
        if ($byPid.ContainsKey($op)) {
            foreach ($r in $order) { if ([int]$r.pid -eq $op) { $nm = $r.name; break } }
        }
        $lsev = 'med'
        if ($lp -in @(135, 139, 445) -and $nm -in @('System', 'svchost.exe', 'lsass.exe')) { $lsev = 'low' }
        & $add ('FLOW-LISTEN-' + [string]$lp) $lsev ('Sensitive port listening: ' + [string]$lp + ' (' + $nm + ')') ([string]$l.LocalAddress + ':' + [string]$lp) 'Limit the listener to localhost or the management network. Verify the service is required and patched, and confirm the firewall scope.' 'exposure-review'
    }

    $high = 0
    $med = 0
    $low = 0
    foreach ($f in $findings) {
        if ($f.sev -eq 'high') { $high++ } elseif ($f.sev -eq 'med') { $med++ } elseif ($f.sev -eq 'low') { $low++ }
    }

    Write-Evt 'flowmeta' 'info' '' @{
        source = $source; processes = $procRows.Count; shown = $order.Count
        nodes = $nodes.Count; edges = $edges.Count
        connections = @($conns).Count; endpoints = $endpoints.Count
        findings = $findings.Count; high = $high; med = $med; low = $low
        policy = 'Read-only process and socket inventory. Parent links use the live parent PID; Windows reuses PIDs, so an orphan link is not proof of injection.'
        window = (Get-Date).ToString('s')
    }
    foreach ($n in $nodes) { Write-Evt 'flownode' 'info' $n.label $n }
    foreach ($e in $edges) { Write-Evt 'flowedge' 'info' '' $e }
    foreach ($f in $findings) { Write-Evt 'flowfinding' $f.sev $f.title $f }

    $summary = ('Flow map - {0} process(es), {1} endpoint(s), {2} finding(s)' -f $order.Count, $endpoints.Count, $findings.Count)
    $snap = Save-Snapshot 'flow' @{
        summary = $summary; processes = $order.Count; endpoints = $endpoints.Count
        findings = @($findings); nodes = @($nodes); edges = @($edges)
    }
    Write-Evt 'log' 'ok' $summary
    Write-Evt 'done' 'ok' $summary @{
        phase = 'flow'; processes = $order.Count; nodes = $nodes.Count; edges = $edges.Count
        findings = $findings.Count; high = $high; med = $med; low = $low
        snapshot = $snap
    }
}

# ===========================================================================
# Investigate - read-only review of live TCP, DNS and listeners.
# ===========================================================================
function Invoke-Investigate {
    Write-Audit 'investigate' 'Network threat investigation' @{}
    Write-Evt 'log' 'dim' 'Collecting live TCP connections, DNS cache and listeners (read-only).'

    $conns = @()
    try { $conns = @(Get-NetTCPConnection -ErrorAction Stop) } catch { }
    $ownerMap = @{}
    try { $ownerMap = Get-OwnerMap -Ids @($conns | ForEach-Object { [int]$_.OwningProcess } | Sort-Object -Unique) } catch { }
    $arp = Get-ArpTable
    $dns = @()
    try { $dns = @(Get-DnsClientCache -ErrorAction Stop) } catch { }

    $findings = New-Object System.Collections.ArrayList
    $seen = @{}
    $add = {
        param($id, $sev, $title, $detail, $fix, $research)
        if ($seen.ContainsKey($id)) { return }
        $seen[$id] = $true
        [void]$findings.Add(@{ id = $id; sev = $sev; title = $title; detail = $detail; fix = $fix; research = $research })
    }

    $remote = @{}
    $publicCount = 0
    $lateralPeers = @{}
    $lateralPorts = @(135, 139, 445, 3389, 5985, 5986, 22)
    foreach ($c in $conns) {
        $state = [string]$c.State
        if ($state -eq 'Listen') { continue }
        $ip = [string]$c.RemoteAddress
        $port = [int]$c.RemotePort
        if (-not $ip -or $ip -eq '0.0.0.0' -or $ip -eq '::') { continue }
        if (-not $remote.ContainsKey($ip)) {
            $private = Test-PrivateIp $ip
            if (-not $private) { $publicCount++ }
            $mac = ''
            if ($arp.ContainsKey($ip)) { $mac = [string]$arp[$ip] }
            $remote[$ip] = @{
                ip = $ip; private = $private; mac = $mac; conns = 0
                ports = @(); processes = @(); states = @()
            }
        }
        $remote[$ip].conns++
        if ($remote[$ip].ports -notcontains $port) { $remote[$ip].ports += $port }
        $op = [int]$c.OwningProcess
        $nm = 'pid ' + [string]$op
        if ($ownerMap.ContainsKey($op)) { $nm = $nm + ' (' + [string]$ownerMap[$op] + ')' }
        if ($remote[$ip].processes -notcontains $nm) { $remote[$ip].processes += $nm }
        if ($remote[$ip].states -notcontains $state) { $remote[$ip].states += $state }
        if ($port -in $lateralPorts -and (Test-PrivateIp $ip)) {
            $lateralPeers[$ip] = $true
        }
    }

    foreach ($k in @($remote.Keys)) {
        $r = $remote[$k]
        Write-Evt 'invconn' 'info' '' @{
            ip = $r.ip; private = $r.private; mac = $r.mac; conns = $r.conns
            ports = ($r.ports -join ','); processes = ($r.processes -join '; ')
            states = ($r.states -join ',')
        }
    }
    Write-Evt 'invmeta' 'info' '' @{
        connections = @($conns).Count; peers = $remote.Count; publicPeers = $publicCount
        dnsEntries = $dns.Count; findings = 0
        policy = 'Read-only live socket and DNS-cache review. Names and geolocation are not guessed; private/public is computed from the address only.'
        window = (Get-Date).ToString('s')
    }

    if ($lateralPeers.Count -ge 3) {
        & $add 'INV-LATERAL' 'high' ('Multiple peers on lateral ports (' + [string]$lateralPeers.Count + ')') (($lateralPeers.Keys | Select-Object -First 12) -join ', ') 'Confirm the process behind each flow. Built-in Windows traffic does not normally touch 445/135/3389 on several peers in one pass. Check 4624 type 3 and 5140/5145 on the peers.' 'lateral-movement'
    }
    foreach ($r in @($remote.Values)) {
        if ($r.private) { continue }
        foreach ($p in @($r.ports)) {
            if ($p -in @(4444, 5555, 6666, 1337, 31337, 9001)) {
                & $add ('INV-HANDLER-' + $r.ip + '-' + [string]$p) 'high' ('Public egress on a handler-style port: ' + $r.ip + ':' + [string]$p) (($r.processes) -join '; ') 'Identify the process and command line, block the destination at the egress firewall, and preserve the evidence.' 'egress-monitoring'
            }
        }
        if (-not (Test-PrivateIp $r.ip)) {
            $hasName = $false
            foreach ($d in $dns) {
                if ([string]$d.Data -eq $r.ip) { $hasName = $true; break }
            }
            if (-not $hasName -and $r.conns -ge 3) {
                & $add ('INV-RAWIP-' + $r.ip) 'low' ('Repeated direct-IP traffic with no DNS-cache name: ' + $r.ip) ([string]$r.conns + ' connection(s), ports ' + ($r.ports -join ',')) 'Check whether the destination is an approved service reached by IP. Direct IP with no cached name is a review trigger; CDNs and update services can also do this.' 'egress-monitoring'
            }
        }
    }

    $suspectDns = @()
    foreach ($d in $dns) {
        $name = ([string]$d.Entry).ToLower()
        if (-not $name) { continue }
        if ($name -match '(duckdns\.org|no-ip\.org|hopto\.org|ngrok\.io|dyndns\.|zapto\.org|serveo\.net|trycloudflare\.com|workers\.dev|pages\.dev)$') {
            if ($suspectDns -notcontains $name) { $suspectDns += $name }
        }
    }
    if ($suspectDns.Count -gt 0) {
        foreach ($n in @($suspectDns | Select-Object -First 8)) {
            Write-Evt 'invdns' 'info' '' @{ name = $n; note = 'dynamic-DNS or tunnel provider; review whether it is approved' }
        }
        & $add 'INV-DYNDNS' 'med' ('Dynamic-DNS or tunnel name(s) in cache: ' + [string]$suspectDns.Count) (($suspectDns | Select-Object -First 8) -join ', ') 'Confirm whether a developer or agent uses that provider. If not, capture the resolving process and block the domain at the DNS filter.' 'dns-monitoring'
    }

    $listeners = @($conns | Where-Object { [string]$_.State -eq 'Listen' } | Sort-Object LocalPort)
    foreach ($l in @($listeners | Select-Object -First 60)) {
        $op = [int]$l.OwningProcess
        $nm = 'pid ' + [string]$op
        if ($ownerMap.ContainsKey($op)) { $nm = [string]$ownerMap[$op] }
        Write-Evt 'invlisten' 'info' '' @{
            port = [int]$l.LocalPort; address = [string]$l.LocalAddress
            pid = $op; owner = $nm; service = (Get-ServiceName ([int]$l.LocalPort))
        }
    }
    $wild = @($listeners | Where-Object { [string]$_.LocalAddress -in @('0.0.0.0', '::') -and [int]$_.LocalPort -in @(21, 23, 135, 139, 445, 3389, 5900, 5985, 5986) })
    if ($wild.Count -gt 0) {
        & $add 'INV-LISTEN' 'med' ('Sensitive listener on all interfaces (' + [string]$wild.Count + ')') (($wild | ForEach-Object { [string]$_.LocalPort } | Sort-Object -Unique) -join ', ') 'Bind the listener to localhost or the management interface, and confirm the firewall only allows approved sources.' 'exposure-review'
    }

    $high = 0
    foreach ($f in $findings) { if ($f.sev -eq 'high') { $high++ } }
    Write-Evt 'invmeta' 'info' '' @{
        connections = @($conns).Count; peers = $remote.Count; publicPeers = $publicCount
        dnsEntries = $dns.Count; findings = $findings.Count; high = $high
        policy = 'Read-only live socket and DNS-cache review. Names and geolocation are not guessed; private/public is computed from the address only.'
        window = (Get-Date).ToString('s')
    }
    foreach ($f in $findings) { Write-Evt 'invfinding' $f.sev $f.title $f }

    $summary = ('Investigation - {0} peer(s), {1} public, {2} finding(s)' -f $remote.Count, $publicCount, $findings.Count)
    $snap = Save-Snapshot 'investigate' @{
        summary = $summary; peers = @($remote.Values); findings = @($findings)
        listeners = @($listeners | Select-Object -First 120)
    }
    Write-Evt 'log' 'ok' $summary
    Write-Evt 'done' 'ok' $summary @{
        phase = 'investigate'; peers = $remote.Count; publicPeers = $publicCount
        findings = $findings.Count; high = $high; snapshot = $snap
    }
}

# ===========================================================================
# Network inventory - read-only traffic inventory and bounded live sampling.
# Sockets, adapters, routes, DNS cache and process owners only. No packets,
# no payloads, no drivers, no DNS changes, no firewall changes.
# ===========================================================================
function Get-NetPortName {
    param([int]$Port)
    $map = @{
        20 = 'ftp-data'; 21 = 'ftp'; 22 = 'ssh'; 23 = 'telnet'; 25 = 'smtp'
        53 = 'dns'; 67 = 'dhcp'; 68 = 'dhcp'; 69 = 'tftp'; 80 = 'http'
        88 = 'kerberos'; 110 = 'pop3'; 123 = 'ntp'; 135 = 'msrpc'; 139 = 'netbios'
        143 = 'imap'; 161 = 'snmp'; 389 = 'ldap'; 443 = 'https'; 445 = 'smb'
        465 = 'smtps'; 514 = 'syslog'; 587 = 'smtp-submit'; 636 = 'ldaps'
        993 = 'imaps'; 995 = 'pop3s'; 1080 = 'socks'; 1433 = 'mssql'
        1521 = 'oracle'; 2049 = 'nfs'; 3306 = 'mysql'; 3389 = 'rdp'
        4444 = 'handler'; 5432 = 'postgres'; 5900 = 'vnc'; 5985 = 'winrm'
        5986 = 'winrms'; 6379 = 'redis'; 8080 = 'http-alt'; 8443 = 'https-alt'
        9001 = 'tor-or'; 27017 = 'mongo'
    }
    if ($map.ContainsKey($Port)) { return [string]$map[$Port] }
    return ''
}

function Get-BrowserHistory {
    # Explicit opt-in only. Opens local History/places databases in SQLite
    # read-only mode. No profile file is copied, changed or deleted.
    param([switch]$Enabled)

    $result = @{
        enabled = [bool]$Enabled
        status = 'NOT REQUESTED'
        profiles = @()
        rows = 0
        map = @{}
        hosts = @()
        ipmap = @{}
        resolved = 0
        note = 'Browser history is opt-in, read-only and never changed. Only host or resolved-IP matches are attached to browser flows.'
    }
    if (-not $Enabled) { return $result }

    $candidates = @()
    $seenPaths = @()
    $chromiumNames = @(
        @{ name = 'Edge'; root = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') },
        @{ name = 'Chrome'; root = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') },
        @{ name = 'Brave'; root = (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data') },
        @{ name = 'Vivaldi'; root = (Join-Path $env:LOCALAPPDATA 'Vivaldi\User Data') }
    )
    foreach ($spec in $chromiumNames) {
        if (-not (Test-Path -LiteralPath $spec.root)) { continue }
        $paths = @()
        $defaultDb = Join-Path $spec.root 'History'
        if (Test-Path -LiteralPath $defaultDb) { $paths += @{ path = $defaultDb; profile = 'Default' } }
        foreach ($dir in @(Get-ChildItem -LiteralPath $spec.root -Directory -ErrorAction SilentlyContinue)) {
            $db = Join-Path $dir.FullName 'History'
            if (Test-Path -LiteralPath $db) { $paths += @{ path = $db; profile = $dir.Name } }
        }
        foreach ($p in $paths) {
            if ($seenPaths -contains $p.path) { continue }
            $seenPaths += $p.path
            $candidates += @{ path = $p.path; profile = $p.profile; browser = $spec.name; kind = 'chromium' }
        }
    }
    $ffRoot = ''
    if ($env:APPDATA) { $ffRoot = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles' }
    if ($ffRoot -and (Test-Path -LiteralPath $ffRoot)) {
        foreach ($dir in @(Get-ChildItem -LiteralPath $ffRoot -Directory -ErrorAction SilentlyContinue)) {
            $db = Join-Path $dir.FullName 'places.sqlite'
            if ((Test-Path -LiteralPath $db) -and ($seenPaths -notcontains $db)) {
                $seenPaths += $db
                $candidates += @{ path = $db; profile = $dir.Name; browser = 'Firefox'; kind = 'firefox' }
            }
        }
    }
    if ($candidates.Count -eq 0) {
        $result.status = 'NO READABLE PROFILES'
        return $result
    }

    $readerPath = Join-Path $script:State 'net-history-reader.py'
    $reader = @'
import json, sqlite3, sys
from pathlib import Path
from urllib.parse import urlparse
cfg = json.loads(open(sys.argv[1], 'r', encoding='ascii').read())
urls = []
profiles = []
limit = int(cfg.get('limit', 400))
for item in cfg.get('files', []):
    path = item['path']
    browser = item['browser']
    profile = item.get('profile', '')
    base_uri = Path(path).resolve().as_uri() + '?mode=ro'
    last_error = None
    done = False
    for mode_uri in (base_uri, base_uri + '&immutable=1'):
        try:
            con = sqlite3.connect(mode_uri, uri=True, timeout=1)
            if item['kind'] == 'chromium':
                rows = con.execute('SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?', (limit,)).fetchall()
                clock = 'winfile'
            else:
                rows = con.execute('SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT ?', (limit,)).fetchall()
                clock = 'unix'
            for row in rows:
                at = int(row[2] or 0)
                if clock == 'winfile':
                    # Chromium stores microseconds since 1601-01-01.
                    sort = max(0, at - 11644473600000000)
                else:
                    sort = max(0, at)
                urls.append({'host': (urlparse(row[0]).hostname or '').lower(), 'url': row[0], 'title': row[1] or '', 'browser': browser, 'at': at, 'sort': sort, 'clock': clock})
            con.close()
            status = 'ok' if mode_uri == base_uri else 'ok-locked'
            profiles.append({'browser': browser, 'profile': profile, 'status': status, 'rows': len(rows)})
            done = True
            break
        except Exception as ex:
            last_error = ex
            try:
                con.close()
            except Exception:
                pass
    if not done:
        profiles.append({'browser': browser, 'profile': profile, 'status': 'unavailable', 'reason': str(last_error)[:160]})
print(json.dumps({'urls': urls, 'profiles': profiles}))
'@
    try {
        [System.IO.File]::WriteAllText($readerPath, $reader, [Text.Encoding]::ASCII)
    } catch {
        $result.status = 'READER WRITE FAILED'
        return $result
    }

    $cfgPath = Join-Path $script:State 'net-history-request.json'
    $cfg = @{ files = @($candidates); limit = 400 } | ConvertTo-Json -Compress -Depth 5
    try {
        [System.IO.File]::WriteAllText($cfgPath, $cfg, [Text.Encoding]::ASCII)
    } catch {
        $result.status = 'REQUEST WRITE FAILED'
        return $result
    }

    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    $raw = @()
    if ($py) {
        $raw = @(& $py.Source -3.11 $readerPath $cfgPath 2>&1)
    } else {
        $py = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($py) { $raw = @(& $py.Source $readerPath $cfgPath 2>&1) }
    }
    if (-not $py) {
        $result.status = 'PYTHON UNAVAILABLE'
        return $result
    }
    $text = ($raw | ForEach-Object { [string]$_ }) -join "`n"
    $lines = @($text -split "`n" | Where-Object { $_ -match '^\{' })
    if ($lines.Count -eq 0) {
        $result.status = 'READER NO OUTPUT'
        return $result
    }
    try {
        $parsed = $lines[$lines.Count - 1] | ConvertFrom-Json
    } catch {
        $result.status = 'READER PARSE FAILED'
        return $result
    }

    $ordered = @($parsed.urls | Sort-Object -Property @{ Expression = { [long]$_.sort } } -Descending)
    $map = @{}
    $byHost = @{}
    $hostList = New-Object System.Collections.ArrayList
    foreach ($u in $ordered) {
        $hname = ([string]$u.host).ToLowerInvariant().TrimEnd('.')
        if (-not $hname) { continue }
        $entry = @{
            host = $hname; url = [string]$u.url; title = [string]$u.title
            browser = [string]$u.browser; at = [string]$u.at
            sort = [long]$u.sort; clock = [string]$u.clock
        }
        $keys = @($hname)
        if ($hname.StartsWith('www.')) { $keys += $hname.Substring(4) } else { $keys += ('www.' + $hname) }
        foreach ($key in $keys) {
            if (-not $map.ContainsKey($key)) { $map[$key] = New-Object System.Collections.ArrayList }
            if ($map[$key].Count -lt 5) { [void]$map[$key].Add($entry) }
        }
        if (-not $byHost.ContainsKey($hname)) { $byHost[$hname] = New-Object System.Collections.ArrayList }
        if ($byHost[$hname].Count -lt 8) { [void]$byHost[$hname].Add($entry) }
        if ($hname -notmatch '^\d+\.\d+\.\d+\.\d+$' -and $hostList -notcontains $hname -and $hostList.Count -lt 40) {
            [void]$hostList.Add($hname)
        }
    }

    # A browser can use DNS-over-HTTPS, leaving the Windows DNS cache empty even
    # while the socket shows a public IP. With history opt-in already granted,
    # resolve a small bounded set of recent history hosts read-only so a socket
    # IP can be paired with the full URL from history. No browser setting or DNS
    # configuration is changed.
    $ipMap = @{}
    $resolvedHosts = 0
    foreach ($h in @($hostList | Select-Object -First 24)) {
        $answers = @()
        try {
            $answers = @(Resolve-DnsName -Name $h -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                Where-Object { $_.IP4Address })
        } catch { $answers = @() }
        if ($answers.Count -eq 0) { continue }
        $resolvedHosts++
        foreach ($a in $answers) {
            $ip = [string]$a.IP4Address
            if (-not $ip) { continue }
            if (-not $ipMap.ContainsKey($ip)) { $ipMap[$ip] = New-Object System.Collections.ArrayList }
            foreach ($hit in @($byHost[$h])) {
                $dup = $false
                foreach ($old in @($ipMap[$ip])) { if ($old.url -eq $hit.url) { $dup = $true; break } }
                if (-not $dup) { [void]$ipMap[$ip].Add($hit) }
            }
        }
    }

    $result.map = $map
    $result.hosts = @($hostList)
    $result.ipmap = $ipMap
    $result.resolved = $resolvedHosts
    $result.profiles = @($parsed.profiles)
    $result.rows = @($parsed.urls).Count
    $result.status = 'OK'
    return $result
}

function Get-ProcKey {
    param([string]$Name)
    $s = ([string]$Name).ToLowerInvariant()
    if ($s.EndsWith('.exe')) { $s = $s.Substring(0, $s.Length - 4) }
    return $s
}

function Invoke-NetworkInventory {
    param(
        [int]$SampleSec = 0,
        [int]$IntervalSec = 2,
        [int]$MaxFlows = 400,
        [switch]$BrowserHistory
    )

    if ($SampleSec -lt 0) { $SampleSec = 0 }
    if ($SampleSec -gt 120) { $SampleSec = 120 }
    if ($IntervalSec -lt 1) { $IntervalSec = 1 }
    if ($IntervalSec -gt 10) { $IntervalSec = 10 }
    if ($MaxFlows -lt 50) { $MaxFlows = 50 }
    if ($MaxFlows -gt 2000) { $MaxFlows = 2000 }

    $recipe = 'OPTIONAL PACKET CAPTURE (administrator, run it yourself): pktmon start --etw -c 2 -p 0 ; pktmon filter add -p 443 ; reproduce the traffic ; pktmon stop ; pktmon etw2net C:\Temp\NtCapture.etl . NetTruder never runs pktmon, installs drivers or reads payloads.'

    Write-Audit 'netinv' 'Network traffic inventory' @{
        sampleSec = $SampleSec; intervalSec = $IntervalSec; maxFlows = $MaxFlows
        browserHistory = [bool]$BrowserHistory
    }
    Write-Evt 'log' 'dim' 'Read-only network inventory: sockets, adapters, routes, DNS cache and process owners. No packets or payloads.'
    Write-Evt 'netmeta' 'info' '' @{
        started = (Get-Date).ToString('s'); sampleSec = $SampleSec
        intervalSec = $IntervalSec; maxFlows = $MaxFlows; pktmon = $recipe
        browserHistory = [bool]$BrowserHistory
        policy = 'Connection-level inventory only. Names come from the local DNS cache, not live lookups. Nothing is generated, blocked or modified.'
        limits = 'No packet capture, no payload inspection, no driver install, no DNS changes and no firewall changes.'
        browserAttribution = 'Browser sockets are attributed from the process name, executable path and a bounded parent chain. No process is started or changed.'
        urlPolicy = 'A host-only URL is always derived from the socket and DNS cache. Full URLs require the explicit READ BROWSER HISTORY opt-in; that opt-in also permits a bounded read-only DNS resolution of recent history hosts so an IP-only socket can be paired with its full URL.'
    }

    $history = Get-BrowserHistory -Enabled:$BrowserHistory
    $historyMap = $history.map
    $historyIpMap = $history.ipmap
    Write-Evt 'nethistory' 'info' '' @{
        enabled = [bool]$BrowserHistory; status = [string]$history.status
        profiles = @($history.profiles).Count; rows = [int]$history.rows
        resolved = [int]$history.resolved
        note = [string]$history.note
    }

    $rules = Get-Rules
    $browserProcs = @()
    $browserCandidates = @()
    if ($rules.fanout) { $browserCandidates += @($rules.fanout.browserProcs) }
    $browserCandidates += @($rules.browserProcs)
    $browserCandidates += @('msedge', 'msedgewebview2', 'chrome', 'firefox', 'brave',
        'opera', 'vivaldi', 'iexplore')
    foreach ($bp in $browserCandidates) {
        $b = Get-ProcKey -Name ([string]$bp)
        if ($b -and $browserProcs -notcontains $b) { $browserProcs += $b }
    }
    $browserPathMarkers = @(
        '\microsoft\edge\application\', '\microsoft\edgewebview\application\',
        '\google\chrome\application\', '\mozilla firefox\',
        '\bravesoftware\brave-browser\', '\opera\', '\vivaldi\'
    )
    $systemProcs = @('system', 'svchost', 'lsass', 'services', 'smss', 'csrss', 'wininit',
        'winlogon', 'msmpeng', 'nissrv', 'securityhealthservice', 'audiodg', 'fontdrvhost',
        'wudfhost', 'wlanext')

    # ---- adapters and routes: how traffic leaves and arrives -----------------
    $ifMap = @{}
    $nics = @()
    try { $nics = @(Get-NetIPConfiguration -ErrorAction Stop) } catch { }
    foreach ($n in $nics) {
        $idx = [int]$n.InterfaceIndex
        $ifMap[[string]$idx] = [string]$n.InterfaceAlias
        $v4 = ''; $prefix = ''; $gw = ''
        $dnsList = @()
        foreach ($a in @($n.IPv4Address)) {
            if ($a) { $v4 = [string]$a.IPAddress; $prefix = [string]$a.PrefixLength; break }
        }
        foreach ($g in @($n.IPv4DefaultGateway)) { if ($g) { $gw = [string]$g.NextHop; break } }
        foreach ($d in @($n.DNSServer)) {
            if ($d -and [string]$d.AddressFamily -eq 'IPv4') { $dnsList += [string]$d.IPAddress }
        }
        $mac = ''; $status = ''; $speed = ''; $iftype = ''
        try {
            $ad = Get-NetAdapter -InterfaceIndex $idx -ErrorAction Stop
            $mac = [string]$ad.MacAddress; $status = [string]$ad.Status
            $speed = [string]$ad.LinkSpeed; $iftype = [string]$ad.InterfaceType
        } catch { }
        Write-Evt 'netadapter' 'info' '' @{
            name = [string]$n.InterfaceAlias; index = $idx; mac = $mac
            ipv4 = $v4; prefix = $prefix; gateway = $gw; dns = ($dnsList -join ',')
            status = $status; speed = $speed; type = $iftype
        }
    }
    $routeCount = 0
    try {
        $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { [string]$_.DestinationPrefix -ne '255.255.255.255/32' } |
            Select-Object -First 80)
        foreach ($r in $routes) {
            $iname = [string]$r.InterfaceIndex
            if ($ifMap.ContainsKey($iname)) { $iname = [string]$ifMap[$iname] }
            $next = [string]$r.NextHop
            Write-Evt 'netroute' 'info' '' @{
                destination = [string]$r.DestinationPrefix; gateway = $next
                interface = $iname; metric = [int]$r.RouteMetric
                scope = $(if ($next -eq '0.0.0.0') { 'on-link' } else { 'via-gateway' })
            }
            $routeCount++
        }
    } catch { Write-Evt 'log' 'warn' 'Route table was not readable on this host.' }

    # ---- DNS cache and process metadata ------------------------------------
    $dnsMap = @{}
    $dnsCount = 0
    try {
        $dns = @(Get-DnsClientCache -ErrorAction Stop)
        $dnsCount = $dns.Count
        foreach ($d in $dns) {
            $ip = [string]$d.Data; $nm = [string]$d.Entry
            if (-not $ip -or -not $nm) { continue }
            if (-not $dnsMap.ContainsKey($ip)) { $dnsMap[$ip] = $nm }
        }
    } catch { }

    $conns = @()
    $udps = @()
    try { $conns = @(Get-NetTCPConnection -ErrorAction Stop) } catch { }
    try { $udps = @(Get-NetUDPEndpoint -ErrorAction Stop) } catch { }
    $pids = @()
    foreach ($c in $conns) { $pids += [int]$c.OwningProcess }
    foreach ($u in $udps) { $pids += [int]$u.OwningProcess }
    $ownerMap = @{}
    try { $ownerMap = Get-OwnerMap -Ids @($pids | Sort-Object -Unique) } catch { }

    $procs = @{}
    try {
        foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
            $procs[[int]$p.ProcessId] = @{
                name = [string]$p.Name; path = [string]$p.ExecutablePath
                parent = [int]$p.ParentProcessId
                cmd = (Get-MaskedText -Text ([string]$p.CommandLine) -Max 160)
            }
        }
    } catch { }

    # Browser attribution is read-only: process name, install path and a bounded
    # parent chain. This catches Edge/Chrome network children and WebView2 hosts
    # without launching or changing any process.
    function Test-BrowserProc {
        param([int]$ProcId)
        $seen = @{}
        $cur = [int]$ProcId
        $depth = 0
        while ($depth -lt 8 -and $cur -gt 0 -and -not $seen.ContainsKey($cur)) {
            $seen[$cur] = $true
            if (-not $procs.ContainsKey($cur)) { break }
            $rec = $procs[$cur]
            $nm = Get-ProcKey -Name ([string]$rec.name)
            if ($browserProcs -contains $nm) { return $true }
            $lowerPath = ([string]$rec.path).ToLowerInvariant()
            foreach ($marker in $browserPathMarkers) {
                if ($lowerPath.IndexOf($marker) -ge 0) { return $true }
            }
            $cur = [int]$rec.parent
            $depth++
        }
        return $false
    }

    $listenPorts = @()
    foreach ($c in $conns) {
        if ([string]$c.State -eq 'Listen') { $listenPorts += [int]$c.LocalPort }
    }

    # ---- flow accumulator ---------------------------------------------------
    $flows = New-Object System.Collections.ArrayList
    $flowIndex = @{}
    $nodeIndex = @{}
    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    function Add-NetNode {
        param($Id, $Label, $Type, $Colour, $Detail, $Seed, $Graph = '')
        if (-not $Id) { return }
        if (-not $nodeIndex.ContainsKey($Id)) {
            $nodeIndex[$Id] = $true
            [void]$nodes.Add(@{
                id = $Id; label = $Label; type = $Type; colour = $Colour
                detail = $Detail; sev = $Seed; nodeClass = $Type; graph = $Graph
            })
        }
    }

    function Get-FlowUrl {
        param([string]$HostName, [string]$RemoteAddr, [int]$RemotePort, [string]$FlowClass)

        $scheme = 'https'
        if ($RemotePort -in @(80, 8080)) { $scheme = 'http' }
        $base = $HostName
        if (-not $base -and $RemoteAddr -and $RemoteAddr -ne '-') { $base = $RemoteAddr }
        $derived = ''
        if ($base) {
            $derived = $scheme + '://' + $base
            if ($RemotePort -and $RemotePort -notin @(80, 443, 8080, 8443)) {
                $derived += ':' + [string]$RemotePort
            }
            $derived += '/'
        }

        $url = $derived
        $source = 'derived-endpoint'
        $title = ''
        $visited = ''
        $browser = ''
        $historyHost = ''
        $urlCandidates = @()
        if ($FlowClass -eq 'browser') {
            $hit = $null
            if ($HostName) {
                $key = ([string]$HostName).ToLowerInvariant().TrimEnd('.')
                if ($historyMap.ContainsKey($key)) { $hit = $historyMap[$key][0] }
            }
            if ($RemoteAddr -and $RemoteAddr -ne '-' -and $historyIpMap.ContainsKey($RemoteAddr)) {
                $ipCandidates = @($historyIpMap[$RemoteAddr] | Sort-Object -Property @{ Expression = { [long]$_.sort } } -Descending)
                if ($ipCandidates.Count -gt 0) {
                    $urlCandidates = @($ipCandidates | Select-Object -First 4)
                    if (-not $hit) { $hit = $urlCandidates[0] }
                }
            }
            if ($hit) {
                $url = [string]$hit.url
                $source = 'browser-history'
                $title = [string]$hit.title
                $visited = [string]$hit.at
                $browser = [string]$hit.browser
                $historyHost = [string]$hit.host
                if ($urlCandidates.Count -eq 0) { $urlCandidates = @($hit) }
            }
        }
        return @{
            url = $url; derived = $derived; source = $source
            title = $title; visited = $visited; browser = $browser
            historyHost = $historyHost; candidates = @($urlCandidates | ForEach-Object { [string]$_.url })
        }
    }

    $stamp = (Get-Date).ToString('s')
    [void]$nodes.Add(@{
        id = 'local'; label = 'THIS HOST'; type = 'local'; colour = '#35f0a0'
        detail = 'Local sockets and listeners'; sev = 'info'; nodeClass = 'local'
    })
    $nodeIndex['local'] = $true
    [void]$nodes.Add(@{
        id = 'blocal'; label = 'BROWSER WEB'; type = 'browser'; colour = '#38bdf8'
        detail = 'Browser sockets only'; sev = 'info'; nodeClass = 'browser'; graph = 'browser'
    })
    $nodeIndex['blocal'] = $true

    function Add-NetFlow {
        param(
            $Proto, $Direction, $LocalAddr, $LocalPort, $RemoteAddr, $RemotePort,
            $StateName, $OwnerPid, $When
        )
        $lp = [int]$LocalPort
        $rp = [int]$RemotePort
        $pa = [string]$LocalAddr
        $ra = [string]$RemoteAddr
        $key = $Proto + '|' + $pa + ':' + [string]$lp + '|' + $ra + ':' + [string]$rp + '|' + [string]$OwnerPid
        $pn = ''; $pp = ''; $parent = 0; $cmd = ''
        if ($procs.ContainsKey([int]$OwnerPid)) {
            $pn = [string]$procs[[int]$OwnerPid].name
            $pp = [string]$procs[[int]$OwnerPid].path
            $parent = [int]$procs[[int]$OwnerPid].parent
            $cmd = [string]$procs[[int]$OwnerPid].cmd
        }
        $owner = ''
        if ($ownerMap.ContainsKey([int]$OwnerPid)) { $owner = [string]$ownerMap[[int]$OwnerPid] }
        $pkey = Get-ProcKey -Name $pn
        $cls = 'background'
        if ([int]$OwnerPid -eq 4 -or [int]$OwnerPid -eq 0) { $cls = 'system' }
        elseif (Test-BrowserProc -ProcId ([int]$OwnerPid)) { $cls = 'browser' }
        elseif ($systemProcs -contains $pkey) { $cls = 'system' }

        $hostName = ''
        if ($ra -and $dnsMap.ContainsKey($ra)) { $hostName = [string]$dnsMap[$ra] }
        $urlInfo = Get-FlowUrl -HostName $hostName -RemoteAddr $ra -RemotePort $rp -FlowClass $cls
        $url = [string]$urlInfo.url
        $urlSource = [string]$urlInfo.source
        $urlTitle = [string]$urlInfo.title
        $urlVisited = [string]$urlInfo.visited
        $urlBrowser = [string]$urlInfo.browser
        $urlHost = [string]$urlInfo.historyHost
        $urlCandidates = @($urlInfo.candidates)
        $svc = Get-NetPortName -Port $rp
        $private = $false
        if ($ra -and $ra -ne '-') { $private = Test-PrivateIp $ra }
        $colour = '#ffb020'
        if ($cls -eq 'browser') { $colour = '#38bdf8' }
        elseif ($cls -eq 'system') { $colour = '#35f0a0' }

        if ($flowIndex.ContainsKey($key)) {
            $ix = [int]$flowIndex[$key]
            $flows[$ix].lastSeen = $When
            $flows[$ix].samples = [int]$flows[$ix].samples + 1
            return
        }
        if ($flows.Count -ge $MaxFlows) { return }

        $why = 'Local process opened this connection to a remote endpoint. Direction is inferred from the local listening-port set. No packets or payloads are inspected.'
        $fix = 'Confirm the process and destination are approved. Review egress in Windows Firewall logs, Sysmon event 3 and DNS logs.'
        if ($Direction -eq 'inbound') {
            $why = 'A remote endpoint initiated contact with a local listener. The 4-tuple and owner are read from Get-NetTCPConnection; the name is from the local DNS cache.'
            $fix = 'Confirm the listener is approved. Scope the source addresses with Windows Firewall; never disable the firewall to solve this.'
        } elseif ($Direction -eq 'listen') {
            $why = 'Local socket is waiting for inbound connections. This is an arrival path, not yet a session.'
            $fix = 'Bind only where needed and restrict allowed sources with Windows Firewall.'
        } elseif ($Direction -eq 'udp') {
            $why = 'Local UDP endpoint. UDP has no connection state, so only the local bind and owner are measured.'
            $fix = 'Confirm the service that owns the port. Monitor unexpected UDP endpoints with Sysmon event 3 and firewall logs.'
        }

        $row = @{
            id = $key; proto = $Proto; dir = $Direction
            local = ($pa + ':' + [string]$lp); remote = ($ra + ':' + [string]$rp)
            localAddr = $pa; localPort = $lp; remoteAddr = $ra; remotePort = $rp
            host = $hostName; state = [string]$StateName; pid = [int]$OwnerPid
            name = $pn; path = $pp; owner = $owner; parent = $parent; cmd = $cmd
            cls = $cls; portName = $svc; private = $private
            url = $url; derivedUrl = [string]$urlInfo.derived; urlSource = $urlSource
            urlTitle = $urlTitle; urlVisited = $urlVisited; urlBrowser = $urlBrowser; urlHost = $urlHost
            urlCandidates = @($urlCandidates)
            firstSeen = $When; lastSeen = $When; samples = 1
            why = $why; fix = $fix
            evidence = 'Get-NetTCPConnection/Get-NetUDPEndpoint + Win32_Process + local DNS cache'
        }
        $flowIndex[$key] = $flows.Count
        [void]$flows.Add($row)

        $pidNode = 'p' + [string]([int]$OwnerPid)
        $shortName = $pn
        if (-not $shortName) { $shortName = 'pid ' + [string]$OwnerPid }
        Add-NetNode -Id $pidNode -Label ($shortName + ' (' + [string]$OwnerPid + ')') -Type $cls -Colour $colour -Detail ($pp + ' / ' + $owner) -Seed 'info'
        [void]$edges.Add(@{ from = 'local'; to = $pidNode; label = 'owns'; colour = '#3d9c7a' })

        if ($ra -and $ra -ne '-') {
            $safe = ($ra + '-' + [string]$rp) -replace '[^A-Za-z0-9]', '_'
            $rnode = 'r' + $safe
            $label = $url
            if (-not $label) { $label = $ra + ':' + [string]$rp }
            $scope = 'public'
            if ($private) { $scope = 'private' }
            $rdetail = $urlSource + ' / ' + $scope + ' / ' + $svc + ' / ' + [string]$Direction
            if ($urlHost) { $rdetail += ' / history-host: ' + $urlHost }
            if ($urlTitle) { $rdetail += ' / ' + $urlTitle }
            Add-NetNode -Id $rnode -Label $label -Type 'remote' -Colour '#a78bfa' -Detail $rdetail -Seed 'info'
            [void]$edges.Add(@{ from = $pidNode; to = $rnode; label = [string]$Direction; colour = $colour })
        }

        if ($cls -eq 'browser') {
            $bpid = 'bp' + [string]([int]$OwnerPid)
            $bprocessDetail = $pp + ' / ' + $owner
            if ($urlBrowser) { $bprocessDetail += ' / history: ' + $urlBrowser }
            Add-NetNode -Id $bpid -Label ($shortName + ' (' + [string]$OwnerPid + ')') -Type 'browser' -Colour '#38bdf8' -Detail $bprocessDetail -Seed 'info' -Graph 'browser'
            [void]$edges.Add(@{ from = 'blocal'; to = $bpid; label = 'owns'; colour = '#3d9c7a'; graph = 'browser' })
            if ($ra -and $ra -ne '-') {
                $brnode = 'br' + $safe
                $blabel = $url
                if (-not $blabel) { $blabel = $ra + ':' + [string]$rp }
                $bdetail = $urlSource + ' / ' + $svc + ' / ' + [string]$Direction
                if ($urlHost) { $bdetail += ' / history-host: ' + $urlHost }
                if ($urlTitle) { $bdetail += ' / ' + $urlTitle }
                Add-NetNode -Id $brnode -Label $blabel -Type 'url' -Colour '#38bdf8' -Detail $bdetail -Seed 'info' -Graph 'browser'
                [void]$edges.Add(@{ from = $bpid; to = $brnode; label = [string]$Direction; colour = '#38bdf8'; graph = 'browser' })
            }
        }
    }

    foreach ($c in $conns) {
        $state = [string]$c.State
        $dir = 'outbound'
        if ($state -eq 'Listen') { $dir = 'listen' }
        elseif ($listenPorts -contains [int]$c.LocalPort) { $dir = 'inbound' }
        elseif ($state -like '*Wait*' -or $state -eq 'Closed') { $dir = 'recent' }
        Add-NetFlow -Proto 'TCP' -Direction $dir -LocalAddr ([string]$c.LocalAddress) `
            -LocalPort ([int]$c.LocalPort) -RemoteAddr ([string]$c.RemoteAddress) `
            -RemotePort ([int]$c.RemotePort) -StateName $state `
            -OwnerPid ([int]$c.OwningProcess) -When $stamp
    }
    foreach ($u in $udps) {
        Add-NetFlow -Proto 'UDP' -Direction 'udp' -LocalAddr ([string]$u.LocalAddress) `
            -LocalPort ([int]$u.LocalPort) -RemoteAddr '-' -RemotePort 0 `
            -StateName 'bound' -OwnerPid ([int]$u.OwningProcess) -When $stamp
    }

    # ---- bounded live sampling --------------------------------------------
    $ticks = 0
    if ($SampleSec -gt 0) {
        $deadline = (Get-Date).AddSeconds($SampleSec)
        while ($true) {
            if (Test-Path -LiteralPath $script:Stop) { break }
            if ((Get-Date) -gt $deadline) { break }
            Start-Sleep -Seconds $IntervalSec
            if (Test-Path -LiteralPath $script:Stop) { break }
            $ticks++
            try { $conns = @(Get-NetTCPConnection -ErrorAction Stop) } catch { $conns = @() }
            $new = 0
            $now = (Get-Date).ToString('s')
            foreach ($c in $conns) {
                $state = [string]$c.State
                $dir = 'outbound'
                if ($state -eq 'Listen') { $dir = 'listen' }
                elseif ($listenPorts -contains [int]$c.LocalPort) { $dir = 'inbound' }
                elseif ($state -like '*Wait*' -or $state -eq 'Closed') { $dir = 'recent' }
                $key = 'TCP|' + [string]$c.LocalAddress + ':' + [string]$c.LocalPort + '|' +
                    [string]$c.RemoteAddress + ':' + [string]$c.RemotePort + '|' + [string]$c.OwningProcess
                $before = $flows.Count
                Add-NetFlow -Proto 'TCP' -Direction $dir -LocalAddr ([string]$c.LocalAddress) `
                    -LocalPort ([int]$c.LocalPort) -RemoteAddr ([string]$c.RemoteAddress) `
                    -RemotePort ([int]$c.RemotePort) -StateName $state `
                    -OwnerPid ([int]$c.OwningProcess) -When $now
                if ($flows.Count -gt $before) { $new++ }
            }
            $bcounts = @{}
            foreach ($f in $flows) {
                $ckey = [string]$f.cls
                if (-not $bcounts.ContainsKey($ckey)) { $bcounts[$ckey] = 0 }
                $bcounts[$ckey] = [int]$bcounts[$ckey] + 1
            }
            Write-Evt 'netsample' 'info' '' @{
                tick = $ticks; time = $now; sockets = @($conns).Count
                flows = $flows.Count; newFlows = $new
                browser = $(if ($bcounts.ContainsKey('browser')) { [int]$bcounts['browser'] } else { 0 })
                background = $(if ($bcounts.ContainsKey('background')) { [int]$bcounts['background'] } else { 0 })
                system = $(if ($bcounts.ContainsKey('system')) { [int]$bcounts['system'] } else { 0 })
                final = $false
            }
        }
    }

    # ---- findings: state plus remediation, never a control-off suggestion --
    $findings = New-Object System.Collections.ArrayList
    $fseen = @{}
    function Add-NetFinding {
        param($Id, $Sev, $Title, $Why, $Fix, $Control, $Evidence)
        if ($fseen.ContainsKey($Id)) { return }
        $fseen[$Id] = $true
        [void]$findings.Add(@{
            id = $Id; sev = $Sev; title = $Title; why = $Why; fix = $Fix
            control = $Control; evidence = $Evidence; detail = $Why
        })
    }

    foreach ($f in $flows) {
        if ([string]$f.dir -eq 'listen' -and [string]$f.localAddr -in @('0.0.0.0', '::', '[::]')) {
            Add-NetFinding -Id ('NET-LISTEN-' + [string]$f.localPort + '-' + [string]$f.pid) -Sev 'med' `
                -Title ('Listener on all interfaces: ' + [string]$f.localPort) `
                -Why ([string]$f.name + ' owns a socket bound to every interface on port ' + [string]$f.localPort + '.') `
                -Fix 'Bind the service to localhost or a management interface and scope the source addresses with Windows Firewall. Do not disable the firewall.' `
                -Control 'exposure-review' -Evidence ([string]$f.local + ' / pid ' + [string]$f.pid)
        }
        if ([string]$f.dir -eq 'listen' -and [int]$f.localPort -eq 3389) {
            Add-NetFinding -Id ('NET-RDP-' + [string]$f.pid) -Sev 'med' -Title 'Remote Desktop listener is active' `
                -Why 'TCP 3389 is listening. Arrivals on this port are remote management sessions.' `
                -Fix 'Confirm Remote Desktop is required, restrict the source IPs at the firewall and keep NLA enabled. Never disable Windows Firewall.' `
                -Control 'exposure-review' -Evidence ([string]$f.local + ' / ' + [string]$f.name)
        }
        if ([int]$f.remotePort -in @(4444, 5555, 6666, 1337, 31337, 9001)) {
            Add-NetFinding -Id ('NET-HANDLER-' + [string]$f.remotePort + '-' + [string]$f.pid) -Sev 'high' `
                -Title ('Egress on handler-style port ' + [string]$f.remotePort) `
                -Why ([string]$f.name + ' contacted ' + [string]$f.remote + ' on a port commonly used by command handlers. This is a review trigger, not proof of compromise.') `
                -Fix 'Identify the process and command line, preserve the event data and block the destination at the egress firewall if it is not approved.' `
                -Control 'egress-monitoring' -Evidence ([string]$f.remote + ' / ' + [string]$f.name)
        }
        if ([string]$f.cls -eq 'background' -and -not [bool]$f.private -and [string]$f.proto -eq 'TCP' -and [int]$f.remotePort -notin @(80, 443, 53, 123)) {
            Add-NetFinding -Id ('NET-BG-' + [string]$f.pid + '-' + [string]$f.remotePort) -Sev 'low' `
                -Title ('Background process egress: ' + [string]$f.name) `
                -Why ([string]$f.name + ' reached a public address on a non-web port. Browser traffic is separated into its own table.') `
                -Fix 'Confirm the owning service is approved and review the destination against threat intelligence. Monitor with firewall logs and Sysmon event 3.' `
                -Control 'egress-monitoring' -Evidence ([string]$f.remote + ' / ' + [string]$f.owner)
        }
        if ([string]$f.cls -eq 'browser' -and [int]$f.remotePort -notin @(80, 443, 8080, 8443, 53, 0)) {
            Add-NetFinding -Id ('NET-BROWSER-' + [string]$f.remotePort) -Sev 'low' `
                -Title ('Browser traffic on non-web port ' + [string]$f.remotePort) `
                -Why ([string]$f.name + ' opened a browser connection outside the usual web ports.') `
                -Fix 'Confirm the site and protocol are expected. Review DNS-cache names and proxy settings before treating this as suspicious.' `
                -Control 'web-traffic-review' -Evidence ([string]$f.remote + ' / ' + [string]$f.host)
        }
        if (-not [bool]$f.private -and [string]$f.remoteAddr -ne '-' -and -not [string]$f.host -and [int]$f.samples -ge 3) {
            Add-NetFinding -Id ('NET-RAWIP-' + [string]$f.remoteAddr) -Sev 'low' `
                -Title ('Direct-IP traffic with no cached name: ' + [string]$f.remoteAddr) `
                -Why ([string]$f.remoteAddr + ' appears in several samples with no DNS-cache entry. CDNs and update services can do this too.') `
                -Fix 'Check whether the destination is an approved service reached by IP. Correlate with DNS logs and the owning process.' `
                -Control 'dns-monitoring' -Evidence ([string]$f.remote + ' / ' + [string]$f.name)
        }
        if ([bool]$f.private -and [int]$f.remotePort -in @(135, 139, 445, 3389, 5985, 5986)) {
            Add-NetFinding -Id ('NET-LATERAL-' + [string]$f.remoteAddr + '-' + [string]$f.remotePort) -Sev 'med' `
                -Title ('Private peer on a management port') `
                -Why ([string]$f.name + ' reached ' + [string]$f.remote + ', a private address on a lateral-management port.') `
                -Fix 'Confirm the process and the peer. Look for 4624 type 3 and 5140/5145 on the target host before treating it as normal administration.' `
                -Control 'lateral-movement' -Evidence ([string]$f.remote + ' / ' + [string]$f.name)
        }
        if (-not [string]$f.name) {
            Add-NetFinding -Id ('NET-NOOWNER-' + [string]$f.pid) -Sev 'info' `
                -Title ('Socket owner not readable for pid ' + [string]$f.pid) `
                -Why 'The socket was observed but process metadata could not be read in this token.' `
                -Fix 'Re-run from an elevated session if you need the process path and owner. Do not weaken any security control to make this readable.' `
                -Control 'visibility-gap' -Evidence ([string]$f.local + ' -> ' + [string]$f.remote)
        }
    }

    $browserFlows = 0; $backgroundFlows = 0; $systemFlows = 0; $inboundFlows = 0; $outboundFlows = 0
    foreach ($f in $flows) {
        if ([string]$f.cls -eq 'browser') { $browserFlows++ }
        elseif ([string]$f.cls -eq 'background') { $backgroundFlows++ }
        elseif ([string]$f.cls -eq 'system') { $systemFlows++ }
        if ([string]$f.dir -eq 'inbound' -or [string]$f.dir -eq 'listen') { $inboundFlows++ }
        elseif ([string]$f.dir -eq 'outbound') { $outboundFlows++ }
    }

    foreach ($n in $nodes) { Write-Evt 'netnode' 'info' ([string]$n.label) $n }
    foreach ($e in $edges) { Write-Evt 'netedge' 'info' '' $e }
    foreach ($f in $flows) { Write-Evt 'netflow' 'info' ([string]$f.local + ' -> ' + [string]$f.remote) $f }
    foreach ($f in $findings) { Write-Evt 'netfinding' ([string]$f.sev) ([string]$f.title) $f }
    Write-Evt 'netsample' 'info' '' @{
        tick = $ticks; time = (Get-Date).ToString('s'); sockets = @($conns).Count
        flows = $flows.Count; newFlows = 0; browser = $browserFlows
        background = $backgroundFlows; system = $systemFlows
        inbound = $inboundFlows; outbound = $outboundFlows
        adapters = @($nics).Count; routes = $routeCount; dnsEntries = $dnsCount
        findings = $findings.Count; final = $true
        browserHistory = [bool]$BrowserHistory; historyStatus = [string]$history.status
        historyRows = [int]$history.rows; historyResolved = [int]$history.resolved
    }

    $summary = ('Network inventory - {0} flow(s), {1} browser, {2} background, {3} finding(s), {4} tick(s)' -f `
        $flows.Count, $browserFlows, $backgroundFlows, $findings.Count, $ticks)
    Write-Audit 'netinv' $summary @{ flows = $flows.Count; findings = $findings.Count; ticks = $ticks }
    Write-Evt 'log' 'ok' $summary
    Write-Evt 'done' 'ok' $summary @{
        phase = 'netinv'; flows = $flows.Count; browser = $browserFlows
        background = $backgroundFlows; system = $systemFlows; findings = $findings.Count
        ticks = $ticks; nodes = $nodes.Count; edges = $edges.Count; sampleSec = $SampleSec
        browserHistory = [bool]$BrowserHistory; historyStatus = [string]$history.status
        historyRows = [int]$history.rows; historyResolved = [int]$history.resolved
        browserNodes = @($nodes | Where-Object { $_.graph -eq 'browser' }).Count
    }
}

# ===========================================================================
# Triage - normalize exported alerts into one prioritised board.
# No message is sent, acknowledged upstream or deleted; decisions are local.
# ===========================================================================
function Get-TriageDecisionMap {
    $p = Join-Path $script:State 'triage-decisions.json'
    $map = @{}
    if (-not (Test-Path -LiteralPath $p)) { return $map }
    try {
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $map }
        $o = $raw | ConvertFrom-Json
        foreach ($k in @($o.PSObject.Properties)) { $map[[string]$k.Name] = $k.Value }
    } catch { }
    return $map
}

function Save-TriageDecision {
    param([string]$Id, [string]$Decision)
    $map = Get-TriageDecisionMap
    $map[$Id] = @{
        decision = $Decision; at = (Get-Date).ToUniversalTime().ToString('o'); by = [string]$env:USERNAME
    }
    $p = Join-Path $script:State 'triage-decisions.json'
    try {
        $json = ConvertTo-Json -InputObject $map -Depth 6
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($p, $json, $enc)
    } catch { }
}

function ConvertFrom-TriageSource {
    param([string]$File)
    $items = @()
    try {
        $raw = Get-Content -LiteralPath $File -Raw -ErrorAction Stop
    } catch { return @() }
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    $trim = $raw.Trim()
    if ($trim.StartsWith('[')) {
        try { return @($trim | ConvertFrom-Json) } catch { }
    }
    if ($trim.StartsWith('{')) {
        try {
            $o = $trim | ConvertFrom-Json
            if ($o.alerts) { return @($o.alerts) }
            if ($o.data -and $o.data.alerts) { return @($o.data.alerts) }
            return @($o)
        } catch { }
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($line in ($raw -split "`n")) {
        $l = $line.Trim()
        if (-not $l) { continue }
        try { [void]$out.Add(($l | ConvertFrom-Json)) } catch { }
    }
    return @($out)
}

function Invoke-Triage {
    $dir = $script:State
    $files = @()
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            $files = @(Get-ChildItem -LiteralPath $Path -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.json', '.ndjson', '.jsonl') } | Sort-Object LastWriteTime -Descending | Select-Object -First 20)
        } elseif (Test-Path -LiteralPath $Path) {
            $files = @(Get-Item -LiteralPath $Path)
        }
    } else {
        $files = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)(triage|alert)' -and $_.Extension -in @('.json', '.ndjson', '.jsonl') } | Sort-Object LastWriteTime -Descending | Select-Object -First 6)
    }

    Write-Audit 'triage' ('Alert triage pass ({0} source file(s))' -f $files.Count) @{ path = $Path }

    if ($ItemId -and $Decision) {
        $d = $Decision.ToLower()
        if ($d -in @('ack', 'suppress', 'resolve', 'reopen')) {
            Save-TriageDecision -Id $ItemId -Decision $d
            Write-Evt 'triageaction' 'ok' ('Decision saved locally: ' + $ItemId + ' -> ' + $d) @{ id = $ItemId; decision = $d }
            Write-Evt 'log' 'dim' 'The upstream tool was not changed. Re-import the export to see the decision applied.'
        } else {
            Write-Evt 'log' 'warn' 'Decision must be ack, suppress, resolve or reopen.'
        }
    }

    if ($files.Count -eq 0) {
        $msg = 'No alert export found. Put an Alertmanager or generic JSON/NDJSON export in ' + $dir + ' (name it triage-*.json) and run again.'
        Write-Evt 'log' 'warn' $msg
        Write-Evt 'done' 'err' $msg @{ phase = 'triage'; items = 0; sources = 0 }
        return
    }

    $decisions = Get-TriageDecisionMap
    $items = @{}
    $sourceRows = @()
    $now = Get-Date
    foreach ($f in $files) {
        $rows = @(ConvertFrom-TriageSource -File $f.FullName)
        $sourceRows += @{ file = $f.Name; rows = $rows.Count; bytes = $f.Length }
        foreach ($a in $rows) {
            if ($null -eq $a) { continue }
            $title = ''
            foreach ($k in @('alertname', 'title', 'summary', 'name', 'message', 'rule')) {
                if ($a.$k) { $title = [string]$a.$k; break }
            }
            if (-not $title) { continue }
            $svc = ''
            foreach ($k in @('service', 'job', 'app', 'component', 'namespace')) {
                if ($a.$k) { $svc = [string]$a.$k; break }
            }
            if (-not $svc -and $a.labels) {
                foreach ($k in @('service', 'job', 'app', 'component')) {
                    if ($a.labels.$k) { $svc = [string]$a.labels.$k; break }
                }
            }
            if (-not $svc) { $svc = 'unassigned' }
            $sev = 'info'
            $rawSev = ''
            foreach ($k in @('severity', 'sev', 'level', 'priority')) {
                if ($a.$k) { $rawSev = [string]$a.$k; break }
            }
            if (-not $rawSev -and $a.labels -and $a.labels.severity) { $rawSev = [string]$a.labels.severity }
            $rawSev = $rawSev.ToLower()
            if ($rawSev -match 'crit|page|p1|fatal|emerg') { $sev = 'high' }
            elseif ($rawSev -match 'high|warn|error|p2') { $sev = 'med' }
            elseif ($rawSev -match 'low|minor|p4') { $sev = 'low' }
            $envName = ''
            foreach ($k in @('env', 'environment', 'stage')) {
                if ($a.$k) { $envName = [string]$a.$k; break }
            }
            if (-not $envName -and $a.labels -and $a.labels.env) { $envName = [string]$a.labels.env }
            $fingerprint = [string]$a.fingerprint
            if (-not $fingerprint) {
                $fingerprint = ([string]$svc + '|' + $title + '|' + [string]$envName).ToLower()
            }
            $started = ''
            foreach ($k in @('startsAt', 'startedAt', 'timestamp', 'time', 'created_at')) {
                if ($a.$k) { $started = [string]$a.$k; break }
            }
            $ageMin = 9999
            if ($started) {
                try {
                    $ageMin = [int]($now - ([datetime]::Parse($started))).TotalMinutes
                } catch { }
            }
            if ($ageMin -lt 0) { $ageMin = 0 }

            if (-not $items.ContainsKey($fingerprint)) {
                $items[$fingerprint] = @{
                    id = $fingerprint; title = $title; service = $svc; sev = $sev
                    env = $envName; source = $f.Name; count = 0; first = $started
                    ageMin = $ageMin; runbook = ''; note = ''; labels = @{}
                    decision = ''; score = 0
                }
            }
            $it = $items[$fingerprint]
            $it.count++
            if ($ageMin -lt $it.ageMin) { $it.ageMin = $ageMin }
            if ($sev -ne 'info') { $it.sev = $sev }
            if ($a.runbook_url) { $it.runbook = [string]$a.runbook_url }
            if ($a.annotations -and $a.annotations.runbook_url) { $it.runbook = [string]$a.annotations.runbook_url }
            if ($a.description) { $it.note = [string]$a.description }
            if ($a.labels) {
                foreach ($k in @($a.labels.PSObject.Properties)) { $it.labels[[string]$k.Name] = [string]$k.Value }
            }
        }
    }

    $rowsOut = New-Object System.Collections.ArrayList
    foreach ($k in $items.Keys) {
        $it = $items[$k]
        $score = 0
        if ($it.sev -eq 'high') { $score += 40 } elseif ($it.sev -eq 'med') { $score += 24 } elseif ($it.sev -eq 'low') { $score += 12 } else { $score += 3 }
        if ($it.ageMin -le 15) { $score += 20 } elseif ($it.ageMin -le 60) { $score += 12 } elseif ($it.ageMin -le 360) { $score += 5 }
        if ($it.count -gt 1) { $score += [Math]::Min(20, ($it.count - 1) * 3) }
        if ($it.env -match '(?i)prod|live|prd') { $score += 10 }
        if ($decisions.ContainsKey($k)) {
            $it.decision = [string]$decisions[$k].decision
            if ($it.decision -eq 'suppress') { $score = [int]($score / 3) }
            if ($it.decision -eq 'resolve') { $score = 0 }
        }
        $it.score = $score
        [void]$rowsOut.Add($it)
    }
    $sorted = @($rowsOut | Sort-Object { [int]$_.score } -Descending)
    foreach ($it in $sorted) { Write-Evt 'triageitem' $(if ($it.sev -eq 'high') { 'high' } else { 'info' }) $it.title $it }

    $groups = @{}
    foreach ($it in $sorted) {
        if (-not $groups.ContainsKey($it.service)) { $groups[$it.service] = @{ service = $it.service; items = 0; top = 0; sev = 'info' } }
        $g = $groups[$it.service]
        $g.items++
        if ($it.score -gt $g.top) { $g.top = $it.score; $g.sev = $it.sev }
    }
    foreach ($g in @($groups.Values | Sort-Object { [int]$_.top } -Descending)) { Write-Evt 'triagesvc' 'info' $g.service $g }

    $plan = @()
    $dupes = @($sorted | Where-Object { $_.count -gt 1 } | Select-Object -First 10)
    if ($dupes.Count -gt 0) {
        $plan += @{ kind = 'dedupe'; text = ('Suppress the repeated fingerprint at the source, not just in this board: ' + [string]$dupes.Count + ' grouped alert(s).'); research = 'alert-fatigue' }
    }
    $stale = @($sorted | Where-Object { $_.ageMin -gt 1440 -and $_.decision -ne 'resolve' } | Select-Object -First 10)
    if ($stale.Count -gt 0) {
        $plan += @{ kind = 'stale'; text = ('Review alerts older than 24h: ' + [string]$stale.Count + '. Resolve, fix the trigger, or retire the rule.'); research = 'alert-fatigue' }
    }
    $noRun = @($sorted | Where-Object { -not $_.runbook } | Select-Object -First 10)
    if ($noRun.Count -gt 0) {
        $plan += @{ kind = 'runbook'; text = ('Add a runbook link to ' + [string]$noRun.Count + ' alert(s) so the next responder does not start from zero.'); research = 'runbook' }
    }
    if ($sorted.Count -eq 0) {
        $plan += @{ kind = 'empty'; text = 'No recognizable alert rows. Supported shapes: Alertmanager {alerts:[...]}, a JSON array, or NDJSON with title/severity/service.'; research = '' }
    }
    foreach ($p in $plan) { Write-Evt 'triageplan' 'info' $p.text $p }

    $summary = ('Triage - {0} unique alert(s) from {1} source(s)' -f $sorted.Count, $files.Count)
    $snap = Save-Snapshot 'triage' @{ summary = $summary; items = @($sorted); plan = @($plan); sources = @($sourceRows) }
    Write-Evt 'log' 'ok' $summary
    Write-Evt 'done' 'ok' $summary @{
        phase = 'triage'; items = $sorted.Count; sources = $files.Count
        high = @($sorted | Where-Object { $_.sev -eq 'high' }).Count
        snapshot = $snap
    }
}

# ===========================================================================
# AV - read-only view of endpoint block telemetry. Never attempts a bypass.
# ===========================================================================
function Add-AvRegister {
    param([string]$Key, $Row)
    $p = Join-Path $script:State 'av-blocks.json'
    $rows = @()
    if (Test-Path -LiteralPath $p) {
        try {
            $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($raw)) { $rows = @($raw | ConvertFrom-Json) }
        } catch { }
    }
    foreach ($r in $rows) { if ([string]$r.key -eq $Key) { return } }
    $rows += $Row
    if ($rows.Count -gt 500) { $rows = @($rows | Select-Object -Last 500) }
    try {
        $json = ConvertTo-Json -InputObject $rows -Depth 8
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($p, $json, $enc)
    } catch { }
}

function Invoke-Av {
    Write-Audit 'av' 'Endpoint block telemetry review' @{}
    Write-Evt 'log' 'dim' 'Reading endpoint block telemetry (read-only). No test is re-run and no bypass is attempted.'
    $products = New-Object System.Collections.ArrayList
    $events = New-Object System.Collections.ArrayList
    $gaps = New-Object System.Collections.ArrayList
    $seen = @{}

    $defSvc = @()
    try {
        $defSvc = @(Get-Service -Name 'WinDefend', 'WdNisSvc', 'Sense' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
    } catch { }
    $defState = 'not running'
    if ($defSvc.Count -gt 0) { $defState = 'running' }
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
    [void]$products.Add(@{
        name = 'Microsoft Defender'; service = $defState
        realtime = $(if ($mp) { [string]$mp.RealTimeProtectionEnabled } else { 'NOT EVALUATED' })
        tamper = $(if ($mp) { [string]$mp.IsTamperProtected } else { 'NOT EVALUATED' })
        log = 'Microsoft-Windows-Windows Defender/Operational'
        note = 'NetTruder never disables, excludes or restarts Defender.'
    })

    if ($mp -and $mp.AntivirusEnabled -eq $false) {
        [void]$gaps.Add(@{ id = 'AV-OFF'; sev = 'high'; title = 'Defender antivirus reports disabled'; detail = 'Get-MpComputerStatus reports AntivirusEnabled=False'; fix = 'Re-enable real-time protection in Windows Security or through your management console. NetTruder never turns a protection off.'; research = 'defender-hardening' })
    }

    $defLogOk = $false
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 1006, 1007, 1015, 5007 } -MaxEvents 120 -ErrorAction Stop)
        $defLogOk = $true
        foreach ($e in $ev) {
            $msg = [string]$e.Message
            $file = ''
            $m = [regex]::Match($msg, '(?im)^\s*(?:Name|Path)\s*:\s*(.+)$')
            if ($m.Success) { $file = $m.Groups[1].Value.Trim() }
            if (-not $file) {
                $m2 = [regex]::Match($msg, '(?im)^\s*Threat\s*:\s*(.+)$')
                if ($m2.Success) { $file = $m2.Groups[1].Value.Trim() }
            }
            $action = 'detected'
            if ([int]$e.Id -in @(1117, 1007)) { $action = 'blocked/cleaned' }
            if ([int]$e.Id -eq 5007) { $action = 'configuration changed' }
            $key = 'def|' + [string]$e.Id + '|' + $e.TimeCreated.ToString('s') + '|' + $file
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $row = @{
                key = $key; product = 'Microsoft Defender'; eventId = [int]$e.Id
                action = $action; at = $e.TimeCreated.ToString('s'); file = $file
                user = ''; level = [string]$e.LevelDisplayName
                detail = ($msg -replace '\s+', ' ').Trim()
                fix = 'A block is a control success. Identify the operator/test, keep the evidence, and use a signed replacement build or an approved exclusion process. Do not disable the control.'
                research = 'av-blocked'
            }
            if ($row.detail.Length -gt 500) { $row.detail = $row.detail.Substring(0, 500) + '...' }
            Add-AvRegister -Key $key -Row $row
            [void]$events.Add($row)
        }
    } catch {
        [void]$gaps.Add(@{ id = 'AV-DEFLOG'; sev = 'low'; title = 'Defender operational log not readable'; detail = $_.Exception.Message; fix = 'Run NetTruder elevated from Launch-Elevated.cmd, or grant the account read access to the Defender operational channel through your normal logging pipeline.'; research = 'telemetry-access' })
    }

    $applocker = 0
    try {
        $al = @(Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 60 -ErrorAction Stop | Where-Object { [int]$_.Id -eq 8004 })
        $applocker = $al.Count
        foreach ($e in $al) {
            $msg = [string]$e.Message
            $file = ''
            $m = [regex]::Match($msg, '(?im)^\s*(?:File|Path)\s*[:=]\s*(.+)$')
            if ($m.Success) { $file = $m.Groups[1].Value.Trim() }
            $key = 'al|' + $e.TimeCreated.ToString('s') + '|' + $file
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $row = @{
                key = $key; product = 'AppLocker'; eventId = 8004; action = 'blocked'
                at = $e.TimeCreated.ToString('s'); file = $file; user = ''; level = 'blocked'
                detail = (($msg -replace '\s+', ' ').Trim())
                fix = 'AppLocker blocked the image by policy. Publish a signed build to an allowed path or update the rule through change control. Do not disable enforcement.'
                research = 'av-blocked'
            }
            if ($row.detail.Length -gt 500) { $row.detail = $row.detail.Substring(0, 500) + '...' }
            Add-AvRegister -Key $key -Row $row
            [void]$events.Add($row)
        }
    } catch {
        [void]$gaps.Add(@{ id = 'AV-ALLOG'; sev = 'info'; title = 'AppLocker EXE/DLL log not readable or not configured'; detail = 'Channel absent, empty or access denied.'; fix = 'If AppLocker is used, confirm the channel is enabled and collected. An unreadable channel is NOT EVALUATED, not a clean result.'; research = 'telemetry-access' })
    }

    $codeIntegrity = 0
    try {
        $ci = @(Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 60 -ErrorAction Stop | Where-Object { [int]$_.Id -in @(3077, 3033, 3034) })
        $codeIntegrity = $ci.Count
        foreach ($e in $ci) {
            $key = 'ci|' + $e.TimeCreated.ToString('s') + '|' + [string]$e.Id
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $row = @{
                key = $key; product = 'Code Integrity'; eventId = [int]$e.Id; action = 'blocked'
                at = $e.TimeCreated.ToString('s'); file = ''; user = ''; level = 'blocked'
                detail = (([string]$e.Message -replace '\s+', ' ').Trim())
                fix = 'A WDAC/CI policy blocked the image. Sign the build with an allowed publisher or request a policy change. Do not disable the policy.'
                research = 'av-blocked'
            }
            if ($row.detail.Length -gt 500) { $row.detail = $row.detail.Substring(0, 500) + '...' }
            Add-AvRegister -Key $key -Row $row
            [void]$events.Add($row)
        }
    } catch { }

    $known = @(
        @{ name = 'McAfee Endpoint Security'; svc = 'masvc|McAfee' },
        @{ name = 'Symantec Endpoint Protection'; svc = 'SepMasterService' },
        @{ name = 'CrowdStrike Falcon'; svc = 'CSFalconService' },
        @{ name = 'SentinelOne'; svc = 'SentinelAgent' },
        @{ name = 'Microsoft Defender for Endpoint'; svc = 'Sense' },
        @{ name = 'Trellix'; svc = 'mfe|Trellix' }
    )
    foreach ($k in $known) {
        $svc = @()
        try { $svc = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $k.svc -or $_.DisplayName -match $k.svc }) } catch { }
        if ($svc.Count -eq 0) { continue }
        $running = @($svc | Where-Object { $_.Status -eq 'Running' })
        [void]$products.Add(@{
            name = $k.name; service = $(if ($running.Count -gt 0) { 'running' } else { 'present / not running' })
            realtime = 'NOT EVALUATED'; tamper = 'NOT EVALUATED'
            log = 'vendor-specific'
            note = 'NetTruder does not parse vendor logs it cannot read and never changes the agent. If the vendor console shows a block, record it in research/blocks.json.'
        })
        if ($k.name -eq 'McAfee Endpoint Security' -and $running.Count -gt 0) {
            [void]$gaps.Add(@{ id = 'AV-ENS'; sev = 'info'; title = 'McAfee ENS is running'; detail = 'ENS block events are vendor-managed. NetTruder does not read or alter ENS configuration.'; fix = 'Use the ePO/ENS console or your SIEM for ENS block evidence. A blocked test is a valid defensive result; do not attempt a bypass.'; research = 'av-blocked' })
        }
    }

    $regPath = Join-Path $script:State 'av-blocks.json'
    $regCount = 0
    if (Test-Path -LiteralPath $regPath) {
        try {
            $raw = Get-Content -LiteralPath $regPath -Raw -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($raw)) { $regCount = @($raw | ConvertFrom-Json).Count }
        } catch { }
    }

    if ($events.Count -gt 0) {
        Write-Evt 'avmeta' 'info' '' @{
            events = $events.Count; register = $regCount; products = @($products)
            defenderLog = $defLogOk; applocker = $applocker; codeIntegrity = $codeIntegrity
            gaps = @($gaps)
            policy = 'A block is a control success. NetTruder records the evidence and the remediation; it never re-runs the blocked action to "prove" it.'
            registerPath = $regPath
            window = (Get-Date).ToString('s')
        }
    } else {
        Write-Evt 'avmeta' 'info' '' @{
            events = 0; register = $regCount; products = @($products)
            defenderLog = $defLogOk; applocker = $applocker; codeIntegrity = $codeIntegrity
            gaps = @($gaps)
            policy = 'A block is a control success. NetTruder records the evidence and the remediation; it never re-runs the blocked action to "prove" it.'
            registerPath = $regPath
            window = (Get-Date).ToString('s')
        }
    }
    foreach ($p in $products) { Write-Evt 'avproduct' 'info' $p.name $p }
    foreach ($e in $events) { Write-Evt 'avevent' 'warn' $e.product $e }
    foreach ($g in $gaps) { Write-Evt 'avfinding' $g.sev $g.title $g }

    $summary = ('Endpoint block review - {0} event(s), {1} product(s), {2} note(s)' -f $events.Count, $products.Count, $gaps.Count)
    $snap = Save-Snapshot 'av' @{ summary = $summary; products = @($products); events = @($events); gaps = @($gaps) }
    Write-Evt 'log' 'ok' $summary
    Write-Evt 'done' 'ok' $summary @{
        phase = 'av'; events = $events.Count; products = $products.Count
        gaps = $gaps.Count; snapshot = $snap
    }
}

# ===========================================================================
# Data security and data management. Read-only check; purge is opt-in.
# ===========================================================================
function Test-Luhn {
    param([string]$Digits)
    $d = $Digits -replace '\D', ''
    if ($d.Length -lt 13 -or $d.Length -gt 19) { return $false }
    $sum = 0
    $alt = $false
    for ($i = $d.Length - 1; $i -ge 0; $i--) {
        $n = [int][string]$d[$i]
        if ($alt) {
            $n = $n * 2
            if ($n -gt 9) { $n = $n - 9 }
        }
        $sum += $n
        $alt = -not $alt
    }
    return ($sum % 10 -eq 0)
}

function Get-DataCategory {
    param([string]$Name, [string]$Ext)
    $n = $Name.ToLower()
    if ($n -match '(?i)(^|[\\/])(\.env|credentials|secrets|id_rsa|id_ed25519|.*\.(pem|pfx|p12|kdbx|key))$') { return 'secrets' }
    if ($Ext -in @('.sql', '.bak', '.dump', '.mdb', '.sqlite')) { return 'database' }
    if ($Ext -in @('.csv', '.tsv', '.xlsx', '.xls', '.parquet')) { return 'dataset' }
    if ($Ext -in @('.log', '.ndjson', '.jsonl')) { return 'logs' }
    if ($Ext -in @('.json', '.yml', '.yaml', '.xml', '.config', '.ini')) { return 'config' }
    if ($Ext -in @('.zip', '.7z', '.tar', '.gz')) { return 'archive' }
    return 'other'
}

function Invoke-DataCheck {
    $root = $Path
    if ([string]::IsNullOrWhiteSpace($root)) { $root = $script:Root }
    if (-not (Test-Path -LiteralPath $root)) {
        Write-Evt 'log' 'err' ('Data path not found: ' + $root)
        Write-Evt 'done' 'err' 'Data check had no path.' @{ phase = 'datacheck'; path = $root }
        return
    }
    try { $root = (Resolve-Path -LiteralPath $root).Path } catch { }
    Write-Audit 'datacheck' ('Data inventory ({0})' -f $root) @{ retentionDays = $RetentionDays }

    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
    $truncated = $false
    if ($files.Count -gt 4000) { $files = @($files | Select-Object -First 4000); $truncated = $true }

    $cats = @{}
    $findings = New-Object System.Collections.ArrayList
    $seen = @{}
    $add = {
        param($id, $sev, $title, $detail, $fix, $research)
        if ($seen.ContainsKey($id)) { return }
        $seen[$id] = $true
        [void]$findings.Add(@{ id = $id; sev = $sev; title = $title; detail = $detail; fix = $fix; research = $research })
    }

    $pii = @{}
    $secretHits = 0
    $old = @()
    $sensitiveSample = @()
    $totalBytes = 0
    $cut = (Get-Date).AddDays(-1 * [Math]::Max(1, $RetentionDays))
    $textExt = @('.txt', '.log', '.json', '.jsonl', '.ndjson', '.csv', '.tsv', '.xml', '.yml', '.yaml', '.ini', '.config', '.md', '.sql', '.ps1', '.js', '.html', '.env')

    foreach ($f in $files) {
        $cat = Get-DataCategory -Name $f.FullName -Ext $f.Extension.ToLower()
        if (-not $cats.ContainsKey($cat)) { $cats[$cat] = @{ name = $cat; files = 0; bytes = 0 } }
        $cats[$cat].files++
        $cats[$cat].bytes += [int64]$f.Length
        $totalBytes += [int64]$f.Length
        if ($f.LastWriteTime -lt $cut) { $old += $f }
        if ($cat -eq 'secrets' -or $f.Extension.ToLower() -in @('.env', '.pem', '.pfx', '.p12', '.kdbx', '.key')) {
            if ($sensitiveSample.Count -lt 40) { $sensitiveSample += $f }
        }
        if ($f.Length -gt 0 -and $f.Length -le 2097152 -and $textExt -contains $f.Extension.ToLower()) {
            $body = ''
            try { $body = [System.IO.File]::ReadAllText($f.FullName) } catch { $body = '' }
            if ($body) {
                if ($body -match '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}') { $pii['email'] = 1 + [int]$pii['email'] }
                $ssn = [regex]::Matches($body, '\b\d{3}-\d{2}-\d{4}\b')
                if ($ssn.Count -gt 0) { $pii['ssn'] = [int]$pii['ssn'] + $ssn.Count }
                if ($body -match '(?i)AKIA[0-9A-Z]{16}') { $secretHits++ }
                if ($body -match '(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----') { $secretHits++ }
                if ($body -match '(?i)\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}') { $secretHits++ }
                foreach ($m in [regex]::Matches($body, '\b(?:\d[ -]?){13,19}\b')) {
                    $digits = ($m.Value -replace '\D', '')
                    if ((Test-Luhn $digits)) { $pii['card'] = 1 + [int]$pii['card'] }
                }
            }
        }
    }

    $aclIssues = @()
    foreach ($f in @($sensitiveSample | Select-Object -First 30)) {
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $f.FullName -ErrorAction Stop } catch { continue }
        foreach ($a in @($acl.Access)) {
            $id = [string]$a.IdentityReference
            if ($id -match '(?i)(Everyone|BUILTIN\\Users|Authenticated Users)$' -and [string]$a.FileSystemRights -match '(?i)(Write|Modify|FullControl|Delete)') {
                $aclIssues += @{ path = $f.FullName; identity = $id; rights = [string]$a.FileSystemRights }
            }
        }
    }

    $bl = $null
    try { $bl = @(Get-BitLockerVolume -ErrorAction Stop) } catch { $bl = $null }
    $encryption = 'NOT EVALUATED'
    if ($bl) {
        $sysVol = @($bl | Where-Object { [string]$_.MountPoint -eq $env:SystemDrive + '\' })
        if ($sysVol.Count -gt 0) { $encryption = [string]$sysVol[0].ProtectionStatus }
    }
    $backup = 'not checked'
    try {
        $bk = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)(backup|\.bak$|\.zip$)' })
        $backup = [string]$bk.Count + ' candidate backup/archive file(s)'
    } catch { }

    if ($secretHits -gt 0) {
        & $add 'DATA-SECRET' 'high' ('Secret material found in text files (' + [string]$secretHits + ')') ('Scan root ' + $root) 'Move secrets to a managed store, rotate them, and add the paths to .gitignore and the backup exclusion list. NetTruder does not print the values.' 'data-secrets'
    }
    if ($pii.ContainsKey('ssn')) {
        & $add 'DATA-SSN' 'high' ('Government-ID pattern found (' + [string]$pii['ssn'] + ')') 'SSN-shaped values were found in readable text files.' 'Remove or tokenise the values, restrict the folder ACL, and confirm the retention policy. Do not copy the file into a ticket.' 'data-pii'
    }
    if ($pii.ContainsKey('card')) {
        & $add 'DATA-CARD' 'high' ('Card-number pattern found (' + [string]$pii['card'] + ')') 'Luhn-valid card-shaped values were found. This is a pattern hit, not proof of live card data.' 'Confirm whether the data is real, remove it from plain files, and verify PCI scope. Never paste the value into a ticket.' 'data-pii'
    }
    if ($pii.ContainsKey('email')) {
        & $add 'DATA-EMAIL' 'med' 'Email addresses present in plain files' ('Root ' + $root + ' contains email-shaped values.') 'Confirm the lawful basis and retention, restrict access, and prefer a tokenised identifier. This is a classification hint, not a breach finding.' 'data-pii'
    }
    if ($aclIssues.Count -gt 0) {
        & $add 'DATA-ACL' 'high' ('Broad write access on sensitive files (' + [string]$aclIssues.Count + ')') (($aclIssues | Select-Object -First 6 | ForEach-Object { $_.identity + ' ' + $_.rights + ' ' + $_.path }) -join ' | ') 'Remove Everyone/Authenticated Users write rights. Grant the minimum group and keep inheritance only where intended.' 'data-acl'
    }
    if ($old.Count -gt 0) {
        & $add 'DATA-RETENTION' 'low' ('Files older than the retention window (' + [string]$old.Count + ')') ('Retention ' + [string]$RetentionDays + ' day(s); oldest ' + $old[0].LastWriteTime.ToString('yyyy-MM-dd')) 'Confirm the retention requirement, archive what must be kept, and delete the rest through the purge action after review.' 'data-retention'
    }
    if ($encryption -ne 'On' -and $encryption -ne 'NOT EVALUATED') {
        & $add 'DATA-ENC' 'med' ('System volume BitLocker status: ' + $encryption) 'Get-BitLockerVolume reported the system volume.' 'Confirm the endpoint encryption policy. NetTruder reports the state and never changes it.' 'data-encryption'
    }
    if ($truncated) {
        & $add 'DATA-TRUNC' 'info' 'File walk truncated at 4000 files' ('Root ' + $root) 'Narrow the path to a project or data folder for a complete inventory.' 'data-inventory'
    }

    $catRows = @($cats.Values | Sort-Object { [int64]$_.bytes } -Descending)
    foreach ($c in $catRows) { Write-Evt 'datacat' 'info' $c.name $c }
    foreach ($f in @($files | Sort-Object Length -Descending | Select-Object -First 60)) {
        Write-Evt 'datafile' 'info' '' @{
            path = $f.FullName; bytes = [int64]$f.Length; modified = $f.LastWriteTime.ToString('s')
            category = (Get-DataCategory -Name $f.FullName -Ext $f.Extension.ToLower())
        }
    }
    Write-Evt 'datameta' 'info' '' @{
        path = $root; files = $files.Count; bytes = $totalBytes; truncated = $truncated
        categories = @($catRows); retentionDays = $RetentionDays
        encryption = $encryption; backup = $backup
        pii = $pii; secretHits = $secretHits; aclIssues = $aclIssues.Count
        policy = 'Read-only classification. Pattern hits are review triggers, not proof of a breach. Purge is separate, previewed, and limited to the NetTruder data root.'
        window = (Get-Date).ToString('s')
    }
    foreach ($f in $findings) { Write-Evt 'datafinding' $f.sev $f.title $f }

    $high = @($findings | Where-Object { $_.sev -eq 'high' }).Count
    $summary = ('Data inventory - {0} file(s), {1} category(ies), {2} finding(s)' -f $files.Count, $catRows.Count, $findings.Count)
    $snap = Save-Snapshot 'datacheck' @{ summary = $summary; categories = @($catRows); findings = @($findings); pii = $pii }
    Write-Evt 'log' 'ok' $summary
    Write-Evt 'done' 'ok' $summary @{
        phase = 'datacheck'; files = $files.Count; bytes = $totalBytes
        findings = $findings.Count; high = $high; snapshot = $snap
    }
}

function Invoke-DataPurge {
    $root = $script:Root
    if ($Yes -and -not $AckRisk) {
        $msg = 'Purge needs both -Yes and -AckRisk. Nothing was deleted.'
        Write-Evt 'log' 'warn' $msg
        Write-Evt 'done' 'err' $msg @{ phase = 'datapurge'; deleted = 0 }
        return
    }
    $targets = New-Object System.Collections.ArrayList
    [void]$targets.Add((Join-Path $root 'runs'))
    [void]$targets.Add((Join-Path $root 'state\snapshots'))
    if ($IncludeAudit) { [void]$targets.Add((Join-Path $root 'audit')) }
    $cut = (Get-Date).AddDays(-1 * [Math]::Max(1, $RetentionDays))
    $preview = New-Object System.Collections.ArrayList
    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t)) { continue }
        $full = ''
        try { $full = (Resolve-Path -LiteralPath $t).Path } catch { continue }
        if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $full -Recurse -File -ErrorAction SilentlyContinue)) {
            if ($f.LastWriteTime -lt $cut) {
                [void]$preview.Add(@{ path = $f.FullName; bytes = [int64]$f.Length; modified = $f.LastWriteTime.ToString('s') })
            }
        }
    }
    $bytes = 0
    foreach ($p in $preview) { $bytes += [int64]$p.bytes }
    foreach ($p in @($preview | Select-Object -First 200)) { Write-Evt 'datapurgeitem' 'info' $p.path $p }

    if (-not $Yes) {
        $msg = ('Purge preview - {0} file(s), {1} bytes older than {2} day(s). Nothing deleted. Re-run with Yes and AckRisk to purge.' -f $preview.Count, $bytes, [Math]::Max(1, $RetentionDays))
        Write-Evt 'log' 'warn' $msg
        Write-Evt 'done' 'ok' $msg @{
            phase = 'datapurge'; preview = $preview.Count; bytes = $bytes
            retentionDays = [Math]::Max(1, $RetentionDays); includeAudit = [bool]$IncludeAudit; deleted = 0
        }
        return
    }

    $deleted = 0
    foreach ($p in $preview) {
        try {
            Remove-Item -LiteralPath $p.path -Force -ErrorAction Stop
            $deleted++
        } catch { }
    }
    Write-Audit 'datapurge' ('Purged {0} NetTruder data file(s)' -f $deleted) @{
        retentionDays = [Math]::Max(1, $RetentionDays); includeAudit = [bool]$IncludeAudit; bytes = $bytes
    }
    $summary = ('Purge - removed {0} of {1} old NetTruder data file(s)' -f $deleted, $preview.Count)
    Write-Evt 'log' 'ok' $summary
    Write-Evt 'done' 'ok' $summary @{
        phase = 'datapurge'; deleted = $deleted; preview = $preview.Count
        bytes = $bytes; retentionDays = [Math]::Max(1, $RetentionDays); includeAudit = [bool]$IncludeAudit
    }
}

function Show-Status {
    $isAdmin = Test-Admin
    $isAdminGroup = Test-AdminGroup
    $accessText = 'standard user'
    if ($isAdmin) { $accessText = 'elevated token' }
    elseif ($isAdminGroup) { $accessText = 'administrator account, filtered token (relaunch elevated for Security log)' }
    Write-Evt 'log' 'ok' ("NetTruder {0} - {1}" -f $script:Version, $accessText)
    $os = [Environment]::OSVersion.VersionString
    Write-Evt 'log' 'dim' ('Host: {0} - OS {1}' -f $env:COMPUTERNAME, $os)
    $ctx = Get-LocalContext
    if ($ctx.ips.Count -gt 0) { Write-Evt 'log' 'dim' ('Local IPv4: {0}' -f ($ctx.ips -join ', ')) }
    if ($ctx.gateway.Count -gt 0) { Write-Evt 'log' 'dim' ('Gateway: {0}' -f ($ctx.gateway -join ', ')) }
    if ($ctx.dns.Count -gt 0) { Write-Evt 'log' 'dim' ('DNS: {0}' -f (($ctx.dns | Select-Object -Unique) -join ', ')) }

    $monitors = 0
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $script:Runs -Filter '*.pid' -ErrorAction Stop)) {
            $procId = 0
            try { $procId = [int]([IO.File]::ReadAllText($f.FullName).Trim()) } catch { $procId = 0 }
            $alive = $false
            if ($procId -gt 0) {
                try { $alive = [bool](Get-Process -Id $procId -ErrorAction Stop) } catch { $alive = $false }
            }
            if ($alive) { $monitors++ } else { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
        }
    } catch { }
    Write-Evt 'log' $(if ($monitors -gt 0) { 'ok' } else { 'dim' }) ('Active IDS monitors: {0}' -f $monitors)

    $rules = Get-Rules
    Write-Evt 'ruleset' 'info' '' @{
        version = [string]$rules.version
        listen  = @($rules.listenPorts).Count
        remote  = @($rules.remotePorts).Count
    }
    Write-Evt 'log' 'dim' ('Ruleset {0} - {1} listener rules - {2} remote-port rules' -f $rules.version, @($rules.listenPorts).Count, @($rules.remotePorts).Count)

    Invoke-Expire -Quiet
    $journal = @(Get-Journal)
    Write-Evt 'blocklist' 'info' '' @{ items = $journal }
    Write-Evt 'log' 'dim' ('Active IPS blocks: {0}' -f $journal.Count)
    Write-Evt 'done' 'ok' 'Status ready.' @{ phase = 'status' }
}

function Show-Rules {
    $rules = Get-Rules
    Write-Evt 'ruleset' 'info' '' @{
        version = [string]$rules.version
        listen  = @($rules.listenPorts).Count
        remote  = @($rules.remotePorts).Count
    }
    foreach ($r in @($rules.listenPorts)) { Write-Evt 'log' 'info' ('listen {0,5}  {1,-10} [{2}] {3}' -f $r.port, $r.service, $r.sev, $r.why) }
    foreach ($r in @($rules.remotePorts)) { Write-Evt 'log' 'info' ('remote {0,5}  {1,-10} [{2}] {3}' -f $r.port, 'egress', $r.sev, $r.why) }
    Write-Evt 'done' 'ok' 'Ruleset printed.' @{ phase = 'rules' }
}

# ===========================================================================
# PowerShell Script Block Logging readout. Read-only: checks policy state and
# samples Event ID 4104 from the Operational log. Never enables, disables or
# clears logging and never executes a script block.
# ===========================================================================
function Get-PsLogEventProperty {
    param($Event, [int]$Index)
    try {
        if ($null -ne $Event -and $null -ne $Event.Properties -and $Event.Properties.Count -gt $Index) {
            $p = $Event.Properties[$Index]
            if ($null -ne $p -and $null -ne $p.Value) { return [string]$p.Value }
        }
    } catch { }
    return ''
}

function Get-PsLogMessageValue {
    param([string]$Message, [string[]]$Names)
    if (-not $Message) { return '' }
    foreach ($name in @($Names)) {
        try {
            $rx = '(?im)^\s*' + [regex]::Escape($name) + '\s*[:=]\s*(.+)$'
            $m = [regex]::Match($Message, $rx)
            if ($m.Success) { return $m.Groups[1].Value.Trim() }
        } catch { }
    }
    return ''
}

function Get-PsLogUser {
    param($Event, [string]$Message)
    $sid = ''
    try { if ($Event -and $Event.UserId) { $sid = [string]$Event.UserId } } catch { }
    $name = Get-PsLogMessageValue -Message $Message -Names @('User', 'User Name', 'Account', 'Subject User Name')
    if ($sid) {
        try {
            $acct = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value
            if ($name -and $acct -and $name.ToLower() -ne $acct.ToLower()) { return $acct + ' (' + $sid + ') / MSG=' + $name }
            return $acct + ' (' + $sid + ')'
        } catch {
            if ($name) { return $name + ' (' + $sid + ')' }
            return $sid
        }
    }
    if ($name) { return $name }
    return 'NOT RECORDED'
}

function Get-PsLogWhere {
    param([string]$Computer, $ProcessId, $ThreadId, [string]$Path)
    $parts = New-Object System.Collections.ArrayList
    if ($Computer) { [void]$parts.Add('HOST=' + $Computer) }
    if ($null -ne $ProcessId -and [string]$ProcessId -ne '') { [void]$parts.Add('PID=' + [string]$ProcessId) }
    if ($null -ne $ThreadId -and [string]$ThreadId -ne '') { [void]$parts.Add('TID=' + [string]$ThreadId) }
    if ($Path) { [void]$parts.Add('PATH=' + (Get-PsLogMaskedText -Text $Path -Max 240)) }
    if ($parts.Count -gt 0) { return ($parts -join ' | ') }
    return 'NOT RECORDED'
}

function Get-PsLogMaskedText {
    param([string]$Text, [int]$Max = 400)
    if (-not $Text) { return '' }
    $s = Get-MaskedText -Text $Text -Max $Max
    $s = $s -replace '(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^;\r\n]{4,}', '$1=***'
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...' }
    return $s
}

function Get-PsLogBase {
    param($Event, [string]$LogName, [string]$Message)
    $log = [string]$Event.LogName
    if (-not $log) { $log = $LogName }
    $sid = ''
    try { if ($Event.UserId) { $sid = [string]$Event.UserId } } catch { }
    return @{
        time = [string]$Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        id = [int]$Event.Id
        level = [string]$Event.LevelDisplayName
        provider = [string]$Event.ProviderName
        computer = [string]$Event.Computer
        processId = [string]$Event.ProcessId
        threadId = [string]$Event.ThreadId
        userId = $sid
        who = Get-PsLogUser -Event $Event -Message $Message
        logName = $log
        recordId = [string]$Event.RecordId
        activityId = [string]$Event.ActivityId
        keywords = [string]$Event.Keywords
        opcode = [string]$Event.OpcodeDisplayName
        task = [string]$Event.TaskDisplayName
        version = [string]$Event.Version
    }
}

function Get-PsLogBlockedEvents {
    param([datetime]$Since)

    $rows = New-Object System.Collections.ArrayList
    $sources = New-Object System.Collections.ArrayList
    $seen = @{}
    $appIds = @(8004, 8005, 8007, 8009, 8011, 8013, 8015, 8017, 8019, 8021, 8023)
    $defs = @(
        @{ name = 'Microsoft Defender'; product = 'Defender'; log = 'Microsoft-Windows-Windows Defender/Operational'; ids = @(1117, 1007) },
        @{ name = 'AppLocker EXE/DLL'; product = 'AppLocker'; log = 'Microsoft-Windows-AppLocker/EXE and DLL'; ids = $appIds },
        @{ name = 'AppLocker MSI/Script'; product = 'AppLocker'; log = 'Microsoft-Windows-AppLocker/MSI and Script'; ids = $appIds },
        @{ name = 'Code Integrity'; product = 'WDAC/CI'; log = 'Microsoft-Windows-CodeIntegrity/Operational'; ids = @(3004, 3033, 3034, 3077) }
    )
    foreach ($def in $defs) {
        $src = @{ name = [string]$def.name; log = [string]$def.log; accessible = $false; rows = 0; error = '' }
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $def.log; Id = $def.ids; StartTime = $Since } -MaxEvents 200 -ErrorAction Stop)
            $src.accessible = $true
            foreach ($e in $events) {
                $msg = [string]$e.Message
                $blob = $msg
                foreach ($p in @($e.Properties)) { $blob = $blob + ' ' + [string]$p.Value }
                if ($blob -notmatch '(?i)powershell(?:\.exe)?|pwsh(?:\.exe)?|System\.Management\.Automation') { continue }
                if ([string]$def.product -eq 'AppLocker' -and $msg -notmatch '(?i)prevented|blocked|denied|not allowed|prohibited') { continue }
                $path = Get-PsLogMessageValue -Message $msg -Names @('Path', 'File', 'Name')
                if (-not $path) {
                    for ($i = 0; $i -lt $e.Properties.Count; $i++) {
                        $v = [string]$e.Properties[$i].Value
                        if ($v -match '(?i)(powershell|pwsh)(\.exe)?$|\.ps[1m]1$|\.dll$') { $path = $v; break }
                    }
                }
                $base = Get-PsLogBase -Event $e -LogName $def.log -Message $msg
                $key = [string]$def.name + '|' + [string]$e.Id + '|' + $e.TimeCreated.ToString('s') + '|' + $path + '|' + $base.recordId
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $action = 'BLOCKED'
                if ([string]$def.product -eq 'Defender') { $action = 'BLOCKED / CLEANED' }
                $row = @{
                    kind = 'block'
                    source = [string]$def.name
                    product = [string]$def.product
                    action = $action
                    time = $base.time
                    id = $base.id
                    level = $base.level
                    provider = $base.provider
                    who = $base.who
                    what = [string]$def.product + ' EVENT ' + [string]$e.Id + ' / ' + $action
                    where = Get-PsLogWhere -Computer $base.computer -ProcessId $base.processId -ThreadId $base.threadId -Path $path
                    path = Get-PsLogMaskedText -Text $path -Max 240
                    computer = $base.computer
                    processId = $base.processId
                    threadId = $base.threadId
                    userId = $base.userId
                    logName = $base.logName
                    recordId = $base.recordId
                    activityId = $base.activityId
                    keywords = $base.keywords
                    opcode = $base.opcode
                    task = $base.task
                    version = $base.version
                    detail = Get-PsLogMaskedText -Text (($msg -replace '\s+', ' ').Trim()) -Max 500
                }
                [void]$rows.Add($row)
            }
        } catch { $src.error = $_.Exception.Message }
        $src.rows = @($rows | Where-Object { $_.source -eq $def.name }).Count
        [void]$sources.Add($src)
    }
    return @{ rows = $rows; sources = $sources }
}

function Invoke-PsLog {
    $logName = 'Microsoft-Windows-PowerShell/Operational'
    $since = (Get-Date).AddDays(-7)
    $enabled = $false
    $policySource = ''
    $logLevel = ''
    $policyKeys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    )
    foreach ($k in $policyKeys) {
        try {
            if (-not (Test-Path -LiteralPath $k)) { continue }
            $p = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
            $v = 0
            if ($p.PSObject.Properties['EnableScriptBlockLogging']) { $v = [int]$p.EnableScriptBlockLogging }
            if ($v -eq 1) {
                $enabled = $true
                $policySource = $k
                if ($p.PSObject.Properties['LogLevel']) { $logLevel = [string]$p.LogLevel } else { $logLevel = '1' }
                break
            }
        } catch { }
    }

    $accessible = $false
    $logError = ''
    try {
        $null = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction Stop
        $accessible = $true
    } catch { $logError = $_.Exception.Message }

    $rows = New-Object System.Collections.ArrayList
    $totalSeen = 0
    if ($enabled -and $accessible) {
        try {
            $filter = @{ LogName = $logName; Id = 4104; StartTime = $since }
            $matches = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction Stop)
            $totalSeen = $matches.Count
            foreach ($ev in @($matches | Select-Object -First 40)) {
                $base = Get-PsLogBase -Event $ev -LogName $logName -Message ([string]$ev.Message)
                $scriptText = Get-PsLogEventProperty -Event $ev -Index 2
                if (-not $scriptText -and $ev.Message) { $scriptText = [string]$ev.Message }
                $msgNo = Get-PsLogEventProperty -Event $ev -Index 0
                $msgTotal = Get-PsLogEventProperty -Event $ev -Index 1
                $scriptId = Get-PsLogEventProperty -Event $ev -Index 3
                $scriptPath = Get-PsLogEventProperty -Event $ev -Index 4
                [void]$rows.Add(@{
                    kind = 'script'
                    time = $base.time
                    id = 4104
                    level = $base.level
                    provider = $base.provider
                    who = $base.who
                    what = 'SCRIPT BLOCK ' + $(if ($scriptId) { $scriptId } else { 'ID NOT RECORDED' }) + ' / MESSAGE ' + $(if ($msgNo) { $msgNo } else { '?' }) + ' OF ' + $(if ($msgTotal) { $msgTotal } else { '?' })
                    where = Get-PsLogWhere -Computer $base.computer -ProcessId $base.processId -ThreadId $base.threadId -Path $scriptPath
                    text = Get-PsLogMaskedText -Text $scriptText -Max 400
                    scriptBlockId = $scriptId
                    path = Get-PsLogMaskedText -Text $scriptPath -Max 240
                    messageNumber = $msgNo
                    messageTotal = $msgTotal
                    computer = $base.computer
                    processId = $base.processId
                    threadId = $base.threadId
                    userId = $base.userId
                    logName = $base.logName
                    recordId = $base.recordId
                    activityId = $base.activityId
                    keywords = $base.keywords
                    opcode = $base.opcode
                    task = $base.task
                    version = $base.version
                })
            }
        } catch { $logError = $_.Exception.Message }
    }

    $blocked = Get-PsLogBlockedEvents -Since $since
    $blockRows = @($blocked.rows)
    $blockSources = @($blocked.sources)
    $readableSources = @($blockSources | Where-Object { $_.accessible }).Count

    Write-Evt 'pslogmeta' $(if ($enabled) { 'ok' } else { 'warn' }) 'PowerShell logging readout complete.' @{
        enabled = [bool]$enabled
        policySource = $policySource
        logLevel = $logLevel
        logName = $logName
        logAccessible = [bool]$accessible
        totalSeen = [int]$totalSeen
        sampled = [int]$rows.Count
        blockedCount = [int]$blockRows.Count
        blockSources = $blockSources
        blockSourceReadable = [int]$readableSources
        logError = $logError
        method = 'Read-only policy check, masked 4104 sample, and read-only AppLocker/WDAC/Defender block-event query. No log is changed, cleared or exported.'
        caveat = 'Attribution shows only fields present in each event. NOT RECORDED means the source did not include it. A captured line or block event is defensive evidence, not a verdict about intent.'
        remediation = 'If logging is off, enable Script Block Logging through Group Policy under Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell, with change control. NetTruder never enables or disables it.'
        generated = [string](Get-Date).ToString('o')
    }
    foreach ($r in $rows) { Write-Evt 'pslogevent' 'info' '' $r }
    foreach ($r in $blockRows) { Write-Evt 'pslogblock' 'warn' $r.product $r }

    $fixLog = @(
        'Enable Script Block Logging via Group Policy with change control: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging.',
        'Keep the Operational log enabled and forward 4104 events to your SIEM with the usual retention and access controls.',
        'Review masked script block text for expected administrative activity before treating it as suspicious.'
    )
    $fixBlock = @(
        'A block is a control success. Preserve the event and identify the operator or scheduled job from the WHO and WHERE fields when present.',
        'Keep AppLocker, WDAC/Code Integrity and Defender operational channels enabled and forwarded. An unreadable or unconfigured channel is NOT EVALUATED, not a clean result.',
        'For vendor EDR blocks, use the vendor console or SIEM and record the result through the normal change process. Do not disable enforcement or re-run a blocked command.'
    )
    if (-not $enabled) {
        Write-Evt 'pslogfinding' 'warn' 'Script Block Logging is not enabled' @{
            id = 'PSLOG-OFF'; title = 'Script Block Logging disabled'; sev = 'med'; state = 'OFF'
            why = 'Event ID 4104 is not produced when Script Block Logging is off, so content-level PowerShell telemetry is missing.'
            detail = 'No policy value EnableScriptBlockLogging=1 was found in HKLM or HKCU PowerShell ScriptBlockLogging policy keys.'
            fix = $fixLog; control = 'TELEMETRY / 4104'; native = ''
        }
    } elseif (-not $accessible) {
        Write-Evt 'pslogfinding' 'warn' 'PowerShell Operational log not readable' @{
            id = 'PSLOG-NOLOG'; title = '4104 log unavailable'; sev = 'med'; state = 'NO ACCESS'
            why = 'The policy is on but the Operational log could not be read from this session.'
            detail = $logError
            fix = $fixLog; control = 'TELEMETRY / 4104'; native = ''
        }
    } elseif ($totalSeen -eq 0) {
        Write-Evt 'pslogfinding' 'info' 'No 4104 events in the last seven days' @{
            id = 'PSLOG-EMPTY'; title = 'No recent script blocks'; sev = 'info'; state = 'EMPTY'
            why = 'Logging is on and the log is readable, but no Event ID 4104 record was found in the sampled window.'
            detail = 'This can be normal on a quiet host. Confirm the log is forwarded and retained before treating a blank view as missing telemetry.'
            fix = $fixLog; control = 'TELEMETRY / 4104'; native = ''
        }
    }
    if ($blockRows.Count -eq 0) {
        Write-Evt 'pslogfinding' 'info' 'No blocked PowerShell events in sampled control logs' @{
            id = 'PSLOG-NOBLOCK'; title = 'No blocked PowerShell events sampled'; sev = 'info'
            state = $(if ($readableSources -eq 0) { 'NOT MEASURED' } else { 'NO BLOCKS SEEN' })
            why = 'No explicit block or prevention event involving PowerShell was found in the sampled AppLocker, WDAC/Code Integrity or Defender channels.'
            detail = 'This does not prove that no block occurred. Check BLOCK SOURCES in the summary and use the SIEM or vendor console for controls NetTruder cannot read.'
            fix = $fixBlock; control = 'CONTROL / PS BLOCK'; native = ''
        }
    }
    Write-Evt 'done' $(if ($enabled) { 'ok' } else { 'warn' }) ('PowerShell logging readout - enabled=' + [string]$enabled + ' - sampled=' + [string]$rows.Count + ' - blocked=' + [string]$blockRows.Count) @{
        phase = 'pslog'; enabled = [bool]$enabled; sampled = [int]$rows.Count; total = [int]$totalSeen
        blocked = [int]$blockRows.Count; blockSourceReadable = [int]$readableSources
    }
}

function Get-ClaimHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').Substring(0, 16)
    } finally {
        $sha.Dispose()
    }
}

function Get-ClaimExcerpt {
    param([string]$Text, [int]$Max = 180)
    $s = [regex]::Replace($Text, '\s+', ' ')
    $s = [regex]::Replace($s, '(?i)\b(password|passwd|pwd|api[ _-]?key|secret|token)\s*[:=]\s*\S+', '[REDACTED]')
    $s = [regex]::Replace($s, '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[EMAIL]')
    $s = [regex]::Replace($s, '(?i)\bhttps?://\S+', '[URL]')
    $s = [regex]::Replace($s, '\b\d+\b', '#')
    $s = $s.Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...' }
    return $s
}

function Get-ClaimRank {
    param([string]$Sev)
    switch ($Sev) {
        'high' { return 3 }
        'med' { return 2 }
        'low' { return 1 }
        default { return 0 }
    }
}

function Get-ClaimLevel {
    param([string]$Sev)
    if ($Sev -eq 'high') { return 'err' }
    if ($Sev -eq 'med') { return 'warn' }
    return 'info'
}

function Invoke-ClaimCheck {
    $rawLength = ([string]$ClaimText).Length
    if ([string]::IsNullOrWhiteSpace($ClaimText)) {
        Write-Evt 'log' 'err' 'Claim text is empty. Paste text into CLAIM CHECK or use -ClaimText.'
        Write-Evt 'done' 'err' 'Claim check had no text.' @{ phase = 'claimcheck'; rows = 0; findings = 0 }
        return
    }
    if ([regex]::IsMatch($ClaimText, '(?i)\b(password|passwd|pwd|api[ _-]?key|secret|token)\s*[:=]\s*\S+')) {
        Write-Evt 'log' 'err' 'Text looks credential-like. Remove secrets before running CLAIM CHECK.'
        Write-Evt 'done' 'err' 'Claim check refused credential-like text.' @{ phase = 'claimcheck'; rows = 0; findings = 0 }
        return
    }

    $text = [string]$ClaimText
    $textTruncated = $false
    if ($text.Length -gt 12000) {
        $text = $text.Substring(0, 12000)
        $textTruncated = $true
    }
    $hash = Get-ClaimHash -Text $text

    $parts = @($text -split '\r?\n+')
    if ($parts.Count -eq 1) { $parts = @($text -split '(?<=[.!?])\s+') }
    $rows = @()
    foreach ($p in $parts) {
        $line = ([string]$p).Trim()
        if ($line) { $rows += $line }
    }
    if ($rows.Count -eq 0) {
        Write-Evt 'log' 'err' 'Claim text had no usable rows.'
        Write-Evt 'done' 'err' 'Claim check had no usable text.' @{ phase = 'claimcheck'; rows = 0; findings = 0 }
        return
    }
    $seenRows = $rows.Count
    $rowTruncated = $false
    if ($rows.Count -gt 80) {
        $rows = @($rows | Select-Object -First 80)
        $rowTruncated = $true
    }

    $verifyFix = @(
        'Find the earliest primary source: original report, court document, dataset, statement or named author.',
        'Check the publication date and whether the text is old material recirculated as new.',
        'Read laterally: leave the page and see how independent, credible sources describe the same claim.',
        'Separate verified facts from interpretation, satire, opinion and edited or missing context.',
        'Record uncertainty. An indicator is a prompt to check, not a verdict about truth.'
    )
    $indicators = @(
        @{ id = 'NT-CL-URG'; label = 'Urgency / sharing pressure'; sev = 'med'; rx = '(?i)\b(breaking|urgent|shocking|act now|share now|before it is too late|must see|you will not believe|do not miss)\b'; why = 'Urgency and sharing pressure can outpace verification and is common in manipulated posts.'; fix = $verifyFix },
        @{ id = 'NT-CL-NOSRC'; label = 'No attribution marker'; sev = 'med'; rx = '(?i)\b(according to|reported by|said in a statement|source:|study|official|department|court|document|published)\b'; why = 'A long claim with no named source marker needs extra lateral reading before it is repeated.'; fix = $verifyFix },
        @{ id = 'NT-CL-ABS'; label = 'Absolute certainty'; sev = 'med'; rx = '(?i)\b(always|never|everyone|nobody|100%|guaranteed|definitely|proven|undeniably)\b'; why = 'Absolute wording is not proof of falsehood, but it often hides nuance or missing qualifiers.'; fix = $verifyFix },
        @{ id = 'NT-CL-EMO'; label = 'Inflammatory wording'; sev = 'med'; rx = '(?i)\b(terrifying|disgusting|traitor|evil|destroy|collapse|catastrophe|outrage|hateful)\b'; why = 'Strong emotional language can be a signal to slow down and check the original context.'; fix = $verifyFix },
        @{ id = 'NT-CL-LINK'; label = 'Link shortener'; sev = 'low'; rx = '(?i)\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd)\b'; why = 'A shortened link hides the destination until it is opened. Do not open unexpected links from an untrusted message.'; fix = $verifyFix },
        @{ id = 'NT-CL-CAPS'; label = 'All-caps emphasis'; sev = 'low'; rx = '\b[A-Z]{4,}\b'; why = 'Repeated all-caps words can be emphasis, quoting or manipulation. Check the source before reacting.'; fix = $verifyFix },
        @{ id = 'NT-CL-NODATE'; label = 'No date marker'; sev = 'low'; rx = '(?i)\b(today|yesterday|monday|tuesday|wednesday|thursday|friday|saturday|sunday|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|(19|20)\d{2})\b'; why = 'No date marker was found. Old claims are often resurfaced without their original date.'; fix = $verifyFix }
    )

    $counts = @{}
    foreach ($ind in $indicators) { $counts[$ind.id] = 0 }
    $rowData = New-Object System.Collections.ArrayList
    $totalMatches = 0

    for ($i = 0; $i -lt $rows.Count; $i++) {
        $row = $rows[$i]
        $flags = @()
        $signals = @()
        $rank = 0
        foreach ($ind in $indicators) {
            $hit = $false
            if ($ind.id -eq 'NT-CL-CAPS') {
                $hit = @([regex]::Matches($row, $ind.rx)).Count -ge 2
            } elseif ($ind.id -eq 'NT-CL-NOSRC') {
                $hit = ($row.Length -ge 60) -and (-not [regex]::IsMatch($row, $ind.rx))
            } elseif ($ind.id -eq 'NT-CL-NODATE') {
                $hit = ($row.Length -ge 60) -and (-not [regex]::IsMatch($row, $ind.rx))
            } else {
                $hit = [regex]::IsMatch($row, $ind.rx)
            }
            if ($hit) {
                $flags += $ind.id
                $signals += $ind.label
                $counts[$ind.id] = [int]$counts[$ind.id] + 1
                $totalMatches++
                $rr = Get-ClaimRank -Sev $ind.sev
                if ($rr -gt $rank) { $rank = $rr }
            }
        }
        $rowSev = 'info'
        if ($rank -ge 3) { $rowSev = 'high' }
        elseif ($rank -eq 2) { $rowSev = 'med' }
        elseif ($rank -eq 1) { $rowSev = 'low' }
        [void]$rowData.Add(@{
            index = ($i + 1)
            chars = [int]$row.Length
            sev = $rowSev
            flags = $flags
            signals = $signals
            excerpt = Get-ClaimExcerpt -Text $row -Max 180
        })
    }

    Write-Audit 'claimcheck' 'Local claim indicator review' @{
        length = [int]$rawLength
        hash = $hash
        rows = [int]$seenRows
        matches = [int]$totalMatches
        textTruncated = [bool]$textTruncated
        rowsTruncated = [bool]$rowTruncated
    }
    Write-Evt 'claimmeta' 'ok' 'Local claim indicators complete - not a truth verdict' @{
        length = [int]$rawLength
        analyzed = [int]$text.Length
        hash = $hash
        rowsSeen = [int]$seenRows
        rowsShown = [int]$rowData.Count
        matches = [int]$totalMatches
        textTruncated = [bool]$textTruncated
        rowsTruncated = [bool]$rowTruncated
        method = 'Local regex heuristics only. No network call, page read, DNS change, host change or policy change.'
        caveat = 'Indicators are prompts for verification, not a verdict about truth. This tool is not an authority on what is true.'
        generated = [string](Get-Date).ToString('o')
    }
    foreach ($r in $rowData) { Write-Evt 'claimrow' 'info' '' $r }

    foreach ($ind in $indicators) {
        $count = [int]$counts[$ind.id]
        $state = $(if ($count -gt 0) { $count.ToString() + ' MATCH(ES) / INDICATOR ONLY' } else { 'NO MATCH IN THIS TEXT' })
        $sev = $(if ($count -gt 0) { $ind.sev } else { 'info' })
        Write-Evt 'claimfind' (Get-ClaimLevel -Sev $sev) $ind.title @{
            id = $ind.id; title = $ind.title; sev = $sev; state = $state
            why = $ind.why; fix = $ind.fix; control = 'INFORMATION INTEGRITY'; matches = $count
        }
    }
    Write-Evt 'claimfind' 'info' 'Claim check is not a truth verdict' @{
        id = 'NT-CL-VERDICT'; title = 'Indicators only - verify with primary sources'; sev = 'info'
        state = 'LOCAL HEURISTICS / NOT A TRUTH VERDICT'
        why = 'Pattern matches can occur in accurate reporting, satire, quoted material and false claims alike.'
        fix = $verifyFix; control = 'INFORMATION INTEGRITY'; matches = 0
    }
    Write-Evt 'done' 'ok' ('Claim check - rows=' + [string]$rowData.Count + ' - matches=' + [string]$totalMatches) @{
        phase = 'claimcheck'; rows = [int]$rowData.Count; findings = (($indicators.Count) + 1); matches = [int]$totalMatches
    }
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
# Data migration runs here, after every function is defined. Calling it near the
# variable block above silently failed inside the try/catch, so legacy NetWatch
# state was never copied forward.
try { $script:DataMigrated = Initialize-DataRoot } catch { $script:DataMigrated = 0 }

$isAdmin = Test-Admin
$isAdminGroup = Test-AdminGroup
Write-Evt 'boot' 'ok' ("NetTruder engine {0} online" -f $script:Version) @{
    mode = $Action; admin = $isAdmin; adminGroup = $isAdminGroup; tokenElevated = $isAdmin
    pid = $PID; version = $script:Version; host = $env:COMPUTERNAME
    dataRoot = $script:Root; migrated = [int]$script:DataMigrated
}

switch ($Action) {
    'status' { Show-Status }
    'rules' { Show-Rules }
    'probe' { Invoke-Probe }
    'scan' {
        $ips = @(Expand-Targets -Spec $Targets)
        if ($ips.Count -eq 0) {
            Write-Evt 'log' 'err' 'No valid targets. Use a private CIDR, range, IP or hostname.'
            Write-Evt 'done' 'err' 'Nothing to scan.' @{ phase = 'sweep'; hosts = 0; ports = 0 }
            break
        }
        if (-not $AllowPublic) {
            $public = @($ips | Where-Object { -not (Test-PrivateIp $_) })
            if ($public.Count -gt 0) {
                Write-Evt 'log' 'warn' ('Skipped {0} non-private address(es). Public scanning needs explicit -AllowPublic.' -f $public.Count)
                $ips = @($ips | Where-Object { Test-PrivateIp $_ })
            }
        }
        if ($ips.Count -eq 0) {
            Write-Evt 'log' 'err' 'Nothing left to scan after the private-range guard.'
            Write-Evt 'done' 'err' 'Guard refused all targets.' @{ phase = 'sweep'; hosts = 0; ports = 0 }
            break
        }
        $portList = @(Get-PortList)
        Write-Evt 'log' 'ok' ('Sweep start - {0} target(s) - {1} port(s) - timeout {2}ms' -f $ips.Count, $portList.Count, $TimeoutMs)
        Write-Audit 'scan' ('Sweep {0} target(s)' -f $ips.Count) @{ targets = ($ips -join ','); ports = $portList.Count; profile = $Profile }

        $alive = @(Invoke-Sweep -Ips $ips)
        $arp = Get-ArpTable
        foreach ($h in $alive) {
            $name = Resolve-IpName -Ip $h.Ip
            $mac = ''
            if ($arp.ContainsKey($h.Ip)) { $mac = $arp[$h.Ip] }
            Write-Evt 'hostmeta' 'info' '' @{ ip = $h.Ip; mac = $mac; name = $name }
        }

        $totalPorts = 0
        $scanned = 0
        foreach ($h in $alive) {
            if (Test-Path -LiteralPath $script:Stop) { Write-Evt 'log' 'warn' 'Sweep aborted by operator.'; break }
            $scanned++
            Write-Evt 'stat' 'info' '' @{ phase = 'ports'; done = $scanned; total = $alive.Count; host = $h.Ip }
            Write-Evt 'log' 'dim' ('Scanning {0}' -f $h.Ip)
            $found = @(Invoke-PortScan -Ip $h.Ip -PortList $portList)
            $totalPorts += $found.Count
        }

        $summary = ('Sweep finished - {0} host(s) up - {1} open port(s)' -f $alive.Count, $totalPorts)
        Write-Evt 'log' 'ok' $summary
        Write-Audit 'scan' $summary @{ hosts = $alive.Count; ports = $totalPorts }
        Write-Evt 'done' 'ok' $summary @{ phase = 'sweep'; hosts = $alive.Count; ports = $totalPorts; scanned = $scanned }
    }
    'watch' {
        Invoke-Expire -Quiet
        Invoke-Watch
    }
    'block' { Invoke-Block -Ip $RemoteIp -Minutes $DurationMin -Reason 'operator' }
    'unblock' { Invoke-Unblock -Ip $RemoteIp }
    'release' { Invoke-Release }
    'expire' { Invoke-Expire; Write-Evt 'done' 'ok' 'Expiry pass complete.' @{ phase = 'expire' } }
    'shell' { Invoke-Shell -Command $CmdLine -Dir $WorkDir -MaxSec $MaxSeconds }
    'processes' { Invoke-Processes }
    'kill' { Invoke-Kill -ProcId $ProcId }
    'research' { Invoke-Research }
    'webscan' { Invoke-WebScan }
    'codeaudit' { Invoke-CodeAudit }
    'coderead' { Invoke-CodeRead }
    'codewrite' { Invoke-CodeWrite }
    'flow' { Invoke-Flow }
    'investigate' { Invoke-Investigate }
    'netinv' { Invoke-NetworkInventory -SampleSec $SampleSec -IntervalSec $IntervalSec -MaxFlows $MaxFlows -BrowserHistory:$BrowserHistory }
    'triage' { Invoke-Triage }
    'av' { Invoke-Av }
    'datacheck' { Invoke-DataCheck }
    'datapurge' { Invoke-DataPurge }
    'pslog' { Invoke-PsLog }
    'claimcheck' { Invoke-ClaimCheck }
}

