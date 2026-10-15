# Security model

VPN credentials are plaintext in the initiating user's data directory, outside the image. The Docker build context is allowlisted and excludes configuration, runtime keys, logs and Git metadata. Keep that directory private.

The Windows service requires UAC, executes the installed binary and keeps policy/relay keys/logs in a protected ProgramData directory. The initiating user can start/stop/query the service but cannot replace its executable. Only public health is shared read-only with Docker.

Forwarding management is opt-in. Recovery state, the service/watchdog/signaling executables and their configuration are protected from standard-user modification. Recovery identifies its original service process by creation time, and a serialized lease prevents an older watchdog from restoring settings underneath a newer service instance.

The container has NET_ADMIN and the tunnel device within its own network namespace, a read-only root, no host networking, no full privileged mode, no Docker socket and no WSL mount. Its route hook does not edit Docker-owned resolv.conf.

Ports bind to Windows localhost. The control API requires a token, validates Host/Origin and exposes no permissive CORS. Dashboard tokens arrive through a URL fragment and are removed from the URL. Configuration responses do not disclose passwords.

Passwords/cookies go through subprocess stdin, not command lines. Cookie-bearing authentication stdout is neither logged nor persisted. A separate password-free tunnel process prevents fresh automatic authentication. Transport reconnect is disabled by default.

Relay egress/corporate DNS bind to tun0. While native routing is active, unavailable VPN traffic fails instead of falling through to direct egress. A stopped/crashed router is not protected by a persistent firewall kill switch. Other VPN software/interface policies can affect interception.

Native and Linux engine archives are version/checksum-pinned; upstream license/source are provided. Docker base images and Debian packages still receive upstream updates on rebuild.
