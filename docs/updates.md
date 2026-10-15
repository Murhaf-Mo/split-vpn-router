# Updates

`vpn upgrade`, the tray update item or the published installer downloads/verifies the latest release MSI. Checkout changes are not published automatically.

MSI stops/removes the service before replacing binaries. After an upgrade Up prepares it again and explicitly connects. Updating files or opening the tray never authenticates. Image source fingerprints trigger a rebuild when contained sources change.

Credentials/lists remain in the existing per-user directory. Stop an old WSL-backed release with that release's Down before migrating; the new runtime runs no WSL cleanup commands.
