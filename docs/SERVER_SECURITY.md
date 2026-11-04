# Server security

Ashapp v0.0.7 adds explicit security choices for Ubuntu 22.04/24.04 and Debian 12. These are administration features, separate from VPN protocols and application updates. Real-VPS provisioning, packet filtering and recovery remain unverified. Local tests replace privileged commands; the SSH-forward test uses local loopback and a fake SSH channel.

## Defaults and management

New setups/templates recommend **Protect SSH with Fail2ban** and **Configure firewall**. Existing serialized templates acquire neither automatically. Adding a network service behind an existing Ashapp firewall requires a reviewed allowlist refresh. **Automatic security updates**, **Disable password SSH login** and SSH-key generation default to off. Unselected setup choices preserve existing policy. Management changes can explicitly turn Ashapp settings on or off.

Use **Manage → Security → Run diagnostics** for the selected IP/SSH port. Unknown status is not healthy or simply off. Draft controls do not change the server until **Review and apply changes** is confirmed. Provider firewalls remain separate.

## SSH keys

Connect with a password or imported private key/passphrase. Generate a unique Ed25519 key per server or import a key in Manage. Ashapp installs only the public key remotely, verifies an independent key login and sudo, and saves the private key in the OS vault. An unavailable vault blocks key-only migration. Private-key fields use an explicit masked Paste action that preserves PEM newlines; the copy icon in Access is explicit. Template key generation makes a fresh key per setup; an explicitly imported key belongs in protected template answers only.

Disabling password login affects every user, including keyboard-interactive passwords. Root denial is separate and requires a verified non-root administrator. Unsupported conditional SSH policy requires manual review. Creating administrators must not implicitly reopen password authentication. Keep a protected recovery key and provider-console access.

## Preview and recovery

A read-only preview captures relevant file hashes and current ports; stale previews are rejected. Changes use a private pending record under `/var/lib/ashapp/security`, a 180-second rollback timer and `ashapp-security-recovery.service` for an interrupted reboot. A new authenticated SSH connection with sudo must confirm before the deadline. Timer/boot recovery waits for a contended security lock instead of abandoning the attempt.

Recovery restores only unchanged transaction files, with original modes. Concurrent edits retain the pending record for manual recovery instead of overwriting them. Inspect private recovery records and service logs through the hosting console if needed. Do not publish complete records/configurations. Dependency installation remains applied; this is not a full VPS rollback. Successful SSH confirmation does not prove every VPN/firewall path.

## Fail2ban

The dedicated `ashapp-sshd` jail uses journald, actual SSH ports, 5 failures within 10 minutes and a 15-minute ban. Existing jails remain unchanged. For a freshly installed package, Ashapp supersedes only its new default SSH jail to support journal-only images without auth.log. Enabling protection also enables normal persistent service startup, even when the daemon is already running; rollback restores its prior activity and enabled state. Masked, runtime-only or other nonstandard startup policy requires manual review rather than silent conversion. Disabling protection disables the Ashapp jail, preserving unrelated protection. Management lists/unbans addresses in this jail only.

Application checks verify parameters, journal matching and installed IPv4/IPv6 actions with temporary documentation-only addresses, preserving prior bans. This is not a real failed-login test. If your own address is banned, use the provider console or wait for expiry; the application cannot bypass SSH filtering.

## Firewall

Dedicated `ASHAPP-IN`/`ASHAPP-DKR` chains use iptables/ip6tables and no-flush table transactions, preserving foreign chains and base policies. Ports include the current SSH listener, existing public services and Docker publications. Existing explicit host rules retain precedence, so earlier allow rules and provider policy still affect exposure. Diagnostics report listeners rather than an Internet scan.

Docker filtering uses its iptables `DOCKER-USER` hook and original destination ports. Active external UFW/firewalld, restrictive existing INPUT base policies and unsupported Docker backends stop automatic setup for manual review. Disabling removes Ashapp chains/plugin only. Later service changes need a reviewed firewall refresh. Persistence uses netfilter-persistent without snapshotting dynamic Docker chains, plus an owned Docker ExecStartPost drop-in to reconcile once Docker is ready. Diagnostics require the relevant container hooks. All persistence helpers, units and drop-ins have ownership/hash checks. Forwarding, IPv6, reboot behavior and simultaneous AWG/VLESS traffic need disposable-VPS validation.

## Automatic OS updates

Off by default. Enabling configures unattended-upgrades and APT timers, permits only distribution security origins and disables automatic reboot. Debian matching follows the release codename/security label rather than moving stable/oldstable suites. Effective APT policy is checked; conflicting higher-priority settings cause failure/recovery.

Disabling removes the Ashapp override, restoring external update policy, which may remain enabled; diagnostics show that effective state separately. Packages remain installed. This does not update pinned sing-box binaries or Docker images. A reboot-required signal does not establish that the next kernel has a working AmneziaWG DKMS module.

## Private SOCKS5

Public mode retains the previous Docker TCP publication and proxy username/password. SOCKS5 authentication is unencrypted; destination HTTPS does not encrypt that separate exchange.

Private mode requires an **already-running stable Docker Engine 28.0.0 or newer** on the server and publishes `127.0.0.1:server-port`. [Older Docker releases can expose localhost publications to nearby hosts](https://docs.docker.com/engine/network/port-publishing/). Ashapp checks the daemon version before Docker startup or any private installation mutation, and before start/restart, credential retrieval and tunnel creation. Install/start a supported daemon manually before choosing private mode. Unknown/prerelease versions are refused; standard upstream versions and known numeric/Ubuntu/Debian/Azure/CE packaging suffixes are accepted. Unsupported existing private services show a warning and remain stoppable or explicitly replaceable with newly entered public-mode credentials. Ashapp does not automatically upgrade/restart a shared Docker daemon. Public mode retains its existing automatic Docker installation/start behavior.

Start the tunnel in Manage and use its displayed **127.0.0.1:local-port** and proxy credentials. The local listener is loopback-only, bounds concurrent forwards and closes with SSH. Keep Ashapp running. This is an SSH forward, not a VPN-only listener or integration with AmneziaVPN's server manager. Mode/credential replacement interrupts existing proxy connections. Stop tunnels before updating Ashapp.

## Required validation

Before production reliance, test fresh/existing Ubuntu and Debian VPSs, custom SSH ports, both authentication methods, journal-only images, both IP families, existing firewall policy, Docker, dual-protocol traffic, repeated setup, concurrent manual edits and disconnect/reboot recovery. Validate native OS-vault/installer retention and macOS sandbox behavior on actual systems. Unit tests and successful builds do not replace those checks.
