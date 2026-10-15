# Native Windows build. Requires Go >= 1.25; no WSL or existing VPN configuration.
param([switch]$Debug, [switch]$SkipRuntime)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Push-Location (Join-Path $root 'controller')
try {
    & go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
    $flags = if ($Debug) { '' } else { '-s -w' }
    $cliArgs = @('build', '-buildvcs=false')
    if ($flags) { $cliArgs += @('-ldflags', $flags) }
    & go @cliArgs -o (Join-Path $root 'vpn.exe') ./cmd/vpn
    if ($LASTEXITCODE -ne 0) { throw 'CLI build failed' }
    & go build -buildvcs=false -ldflags "$flags -H windowsgui" -o (Join-Path $root 'vpn-tray.exe') ./cmd/vpn-tray
    if ($LASTEXITCODE -ne 0) { throw 'Tray build failed' }
} finally { Pop-Location }
if (-not $SkipRuntime) { & (Join-Path $root 'prepare-runtime.ps1') }
Write-Host 'Built vpn.exe and vpn-tray.exe. Use vpn configure, then vpn up.'
