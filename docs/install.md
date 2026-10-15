# Installation

Requires Windows x64, Docker Desktop running Linux containers, and administrator approval for the Windows routing service/virtual adapter. The tool does not install/reconfigure a distro or switch Docker's backend.

```powershell
irm https://raw.githubusercontent.com/Murhaf-Mo/split-vpn-router/main/install.ps1 | iex
```

This fetches the latest **published release**. Build checkout changes locally using `build.ps1` until a new release is published.

The installer verifies the MSI, installs files, checks Docker and runs the configuration wizard. It never connects. First `vpn up` requests UAC for the manual-start service, builds the contained runtime and initiates MFA explicitly.

Before migrating, run the old release's `vpn down` to stop its existing processes cleanly. The new release performs no WSL cleanup commands and unregisters no distros. Recognized legacy proxies are backed up before removal; apps already caching them can need one restart.
