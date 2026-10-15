# Development

Use native Windows Go 1.25 or newer. Compilation needs no WSL or config.toml.

```powershell
.\build.ps1
```

This runs Go tests, builds the CLI/tray and downloads a pinned, checksum-verified engine plus its license/companion DLL. `-Debug` retains symbols; `-SkipRuntime` skips the download when already present.

```powershell
cd controller
go test ./...
go vet ./...
cd ..
python -m unittest discover -s tests -v
```

Python tests require 3.11+; the container uses 3.12. Set `SING_BOX_BIN` to a verified engine to include the localhost encrypted TCP/UDP smoke test. It opens local listeners only and never creates a TUN or authenticates. Go policy tests can export `VPN_ROUTER_CONFIG_FIXTURE` for `sing-box check`.

`internal/backend` controls local Docker; `internal/router` generates policy/manages the service; `internal/platform` locates files; `internal/winproxy` repairs recognized legacy settings. `vpnctl.py` is the passive container API/session manager. `vpnc-script.py` configures only the container's routes. `.dockerignore` excludes secrets from image context.

After building, package the checkout with WiX 6:

```powershell
wix build installer\split-vpn-router.wxs -arch x64 -d Version=0.0.0 -d StagingDir=$PWD -o split-vpn-router-dev.msi
```

CI runs Python/policy tests, builds the image, cross-compiles Windows binaries, downloads the pinned native engine and packages the MSI. Set `VPN_CONTAINER_IMAGE` to a built image to verify passive Docker startup/restart and isolated route-hook/DNS behavior. Live Windows adapter/service and MFA lifecycle testing remains necessary; see [troubleshooting](troubleshooting.md).

Release MSI asset filenames retain the historical `wsl-vpn-router` prefix so existing updater/installer clients continue to work after the repository rename. Development builds refuse published-release upgrades, preventing replacement with an older architecture during testing.
