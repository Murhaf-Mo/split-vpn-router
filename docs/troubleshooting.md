# Troubleshooting and migration

## Docker unavailable

Start Docker Desktop with Linux containers. Up requires a local Windows named-pipe Docker context and rejects remote engines. The tool leaves Docker's backend alone; the VPN hook changes only its container's network namespace.

## Migrating from the old release

Stop the old release using its `vpn down` before upgrading. The new controller runs no WSL cleanup or distro-removal commands. `vpn repair-proxy` recognizes legacy endpoints using the old configuration/PAC log, backs up removed values in `legacy-proxy-backup.json` and preserves unrelated proxies.

Running apps can retain the old environment or their own manual proxy. Restart those apps once or clear their explicit proxy. Windows cannot rewrite every app's private in-memory environment. The new router does not add these settings again.

## Timeout or declined MFA

The VPN remains disconnected until you choose Up/Connect. `auto_reconnect = true` permits existing-cookie transport recovery only. Fresh password authentication always requires an explicit action. Read `vpn logs oc` for server errors.

## VPN connected but routing fails

Check `vpn status` for native routing health as well as the tunnel. Up restores an inactive router using an existing connected VPN session. Check domain/IP rules, precedence, corporate DNS and hosts-file mappings. Both HTTP Git and SSH Git use the adapter; an explicit Git/application proxy can still interfere.

Use IP/CIDR rules for applications whose encrypted DNS and hidden hostnames prevent domain identification. HTTPS paths are unavailable to packet routing. Existing sockets may need to reconnect. Other VPN software, raw sockets, interface binding and firewall policy can affect coverage.

## Internet breaks as the adapter starts

Check IP forwarding on the outbound adapter. A live test reproduced self-captured router sockets when Ethernet forwarding was enabled, even in direct-default mode and with explicit interface binding. `routing.manage_forwarding = true` enables scoped, recoverable management of that setting; otherwise Up refuses the conflicting configuration before MFA. Do not globally disable forwarding on unrelated adapters. If startup fails, `vpn down` stops interception, and the independent recovery process restores recorded forwarding settings.

## Config broken or Docker stopped

`vpn down` works without valid configuration and removes interception before Docker cleanup. Complete service removal is `vpn router-uninstall` from an administrator terminal. OS DNS caches are flushed at adapter start/stop; apps holding their own synthetic DNS answers may need to re-resolve.

## Diagnostics and release validation

Use `vpn logs oc`, `vpn logs proxy`, `vpn logs pac` and `vpn status`. Native logs are in `%ProgramData%\VPNRouter\router.log` and require administrator access.

Before release, verify Docker startup/port forwarding, UAC/service ACLs, adapter create/stop/reload, real TCP/UDP/DNS/private hosts, MFA approve/decline/timeout, VPN expiry, Wi-Fi changes, sleep/resume and coexistence with other installed VPNs. Automated tests and localhost relay checks do not replace these live integration checks.

The 2026-10-15 Windows session verified approved MFA, public HTTPS and ordinary Git, corporate HTTPS, UDP corporate DNS through the encrypted relay, live URL-rule reload without replacing the OpenConnect process, manual disconnect with direct traffic preserved and VPN traffic blocked, and forwarding/adapter restoration after graceful stop and forced termination. Declined/timed-out authentication and disabled transport retries have automated coverage. Sleep/resume, adapter switching and long session expiry remain untested live.
