# Split VPN Router uninstaller.
#
# Invoked by the MSI's "deferred uninstall" custom action (so it runs elevated
# with the install context still available). Can also be run manually:
#   & "C:\Program Files\wsl-vpn-router\uninstall.ps1" [-PurgeData]
#
# Stops the Windows routing service and this tool's Docker container.
# Docker Desktop, its backend, and other containers are preserved.
# Configuration and routing lists are preserved unless -PurgeData is supplied.

[CmdletBinding()]
param(
    [switch]$PurgeData
)

$ErrorActionPreference = 'Continue'  # best-effort; never bail half-way

function Info($m) { Write-Host "    $m" }
function Step($m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "!!  $m" -ForegroundColor Yellow }

$InstallDir = (Get-Item -Path $PSScriptRoot -ErrorAction SilentlyContinue).FullName
if (-not $InstallDir) { $InstallDir = "$env:ProgramFiles\wsl-vpn-router" }
$DataDir    = Join-Path $env:LOCALAPPDATA 'wsl-vpn-router'

# ---------- 1. Tear down Windows-side proxy state via vpn.exe ----------
$vpnExe = Join-Path $InstallDir 'vpn.exe'
if (Test-Path $vpnExe) {
    Step "Running vpn down (stops native routing and the managed container)"
    try {
        & $vpnExe down 2>&1 | ForEach-Object { Info $_ }
    } catch {
        Warn "vpn down failed: $($_.Exception.Message)  (continuing)"
    }
}

# ---------- 3. Remove native router service ----------
if (Test-Path $vpnExe) {
    & $vpnExe router-uninstall
    if ($LASTEXITCODE -ne 0) { Warn "Router service removal failed; rerun vpn router-uninstall as administrator." }
}

# ---------- 2. Kill any lingering processes ----------
Step "Stopping vpn-tray.exe / vpn.exe"
foreach ($name in @('vpn-tray.exe', 'vpn.exe')) {
    Get-Process -Name ($name -replace '\.exe$', '') -ErrorAction SilentlyContinue |
        ForEach-Object {
            Info "kill $($_.ProcessName) pid $($_.Id)"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
}

# ---------- 4. HKCU autostart ----------
Step "Removing HKCU autostart entry"
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Test-Path $runKey) {
    Remove-ItemProperty -Path $runKey -Name 'VpnTray' -ErrorAction SilentlyContinue
}

# ---------- 5. HKLM install marker ----------
Step "Removing HKLM\Software\wsl-vpn-router"
$appKey = 'HKLM:\Software\wsl-vpn-router'
if (Test-Path $appKey) {
    Remove-Item -Path $appKey -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------- 6. Data dir (opt-in) ----------
if ($PurgeData) {
    Step "Purging $DataDir (config.toml + lists + runtime/ logs)"
    if (Test-Path $DataDir) {
        $resolvedData = [IO.Path]::GetFullPath($DataDir).TrimEnd('\')
        $expectedData = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'wsl-vpn-router')).TrimEnd('\')
        if ($resolvedData -ne $expectedData -or $resolvedData -eq [IO.Path]::GetPathRoot($resolvedData)) { throw 'Unsafe data purge path' }
        Remove-Item -LiteralPath $resolvedData -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Info "Preserving $DataDir (use -PurgeData to also remove your config + lists)"
}

Step "Uninstall steps complete. MSI will remove $InstallDir."
