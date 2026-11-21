# NetTruder // LOLBAS Research Lab - inert marker probe
# Token NWPROBE-4104-CONTENT-MARKER is used to identify this script in 4104.
# Appends one line to $env:NETTRUDER_LAB_DIR\markers.log and exits.
# No network, no persistence, no payload, no hidden window.

$dir = $env:NETTRUDER_LAB_DIR
if ([string]::IsNullOrWhiteSpace($dir)) {
    $dir = Join-Path $env:LOCALAPPDATA 'NetTruder\lab'
}
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$line = '{0} | powershell | {1} | {2}@{3}' -f `
    (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), `
    $MyInvocation.MyCommand.Name, `
    $env:USERNAME, `
    $env:COMPUTERNAME

Add-Content -LiteralPath (Join-Path $dir 'markers.log') -Value $line -Encoding ASCII
