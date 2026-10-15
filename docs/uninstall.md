# Uninstall

Run `vpn down`, then uninstall through Windows Settings or run the installed `uninstall.ps1` as administrator. The script removes the native service before terminating tray processes. MSI also stops/removes the service during uninstall/upgrade.

Only this tool's managed container and service are removed. Docker Desktop, other containers, distros and Docker's backend are preserved. Container images can be removed with Docker when no longer needed.

Per-user credentials/lists survive by default. `uninstall.ps1 -PurgeData` deletes the explicitly checked per-user data directory. Protected ProgramData routing executables/diagnostics/cache are retained; administrators can remove them after confirming the service is gone.
