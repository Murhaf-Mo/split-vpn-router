# Download the pinned native routing engine. Does not install a service or change networking.
param([string]$Destination = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$version = '1.14.3'
$expected = 'd8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('vpn-router-runtime-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$archive = Join-Path $temporary 'sing-box.zip'
Invoke-WebRequest "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip" -OutFile $archive -UseBasicParsing
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLower() -ne $expected) { throw 'Routing engine checksum mismatch' }
Expand-Archive -LiteralPath $archive -DestinationPath $temporary
$source = Join-Path $temporary "sing-box-$version-windows-amd64"
Copy-Item -LiteralPath (Join-Path $source 'sing-box.exe') -Destination $Destination
Copy-Item -LiteralPath (Join-Path $source 'libcronet.dll') -Destination $Destination
Copy-Item -LiteralPath (Join-Path $source 'LICENSE') -Destination (Join-Path $Destination 'sing-box-LICENSE.txt')
Write-Host "Verified sing-box $version. No network settings changed."
# Keep the verified download in TEMP for diagnosis; Windows may evict it later.
