# Ashapp

<img src="branding/ashapp.png" width="80" height="80" alt="Ashapp logo">

**Prepare a VPS your way, save the answers as a template, and repeat the setup on your next server.** Ashapp configures an existing Linux VPS over SSH and manages it afterward from Windows or macOS.

Its main feature is a reusable **server setup template**: an administrator account, protected passwords, root SSH and ping policies, package upgrades, VPN protocols, optional SOCKS5 and the first named devices. Review the prefilled answers, run setup, then export each device's connection details. Manual setup follows the same steps. Use it to configure several VPSs consistently and manage them in one place. Keep using AmneziaVPN or another compatible VPN client for the connection.

Open source under the [MIT license](LICENSE). Targets: Windows x64, macOS Intel and macOS Apple Silicon.

**Version 0.0.12** adds a persistent installation journal, explicit setup recovery, deeper diagnostics, reviewed removal of Ashapp-owned changes, Amnezia client links and installation fixes. Shared AmneziaVPN management is **experimental** and may not work with your client version. See [release notes](docs/RELEASE_NOTES.md) and [shared-mode limits](docs/AMNEZIA_SHARED.md).

Client `vpn://` links reuse existing device keys, contain no SSH/admin credentials and never grant server-management access. Shared mode uses a real kernel container; discovery/adoption in the official GUI still need independent verification. Host kernel mode and existing deployments remain supported.

Validation must refer to the current source and release run. Earlier successful VPS experiments and local test counts do not validate later changes. Real Linux/systemd/Docker recovery, external client traffic, GUI adoption, reboot behavior, macOS execution and update/credential retention remain separate checks. The owner will test a second VPS; this patch has not been validated there.

Ashapp installs **AmneziaWG as a Linux kernel module** and/or **VLESS + Reality + XTLS Vision**, manages per-device access and optionally runs an authenticated SOCKS5 proxy in Docker. Both VPN protocols can run on one VPS as independent services. Multiple SSH connections retain independent state, including servers sharing an IP with different SSH ports. The app does not buy VPS instances or run a local VPN tunnel.

## Download v0.0.12

**v0.0.12 adds installation recovery, diagnostics, removal controls and compatibility fixes.** The versioned links below become available as each target finishes validation and publication; the release page shows the uploaded assets. See [update behavior and validation limits](docs/UPDATES.md).

This repository and its releases are **public**. Windows, macOS Intel and macOS Apple Silicon publish independently after their own checks succeed. Each ready target has its own checksum file; combined `SHA256SUMS` appears after all three finish. A source ZIP is not an application installer.

| Computer | Installer | Complete portable archive |
| --- | --- | --- |
| Windows 10/11 x64 | [Install Windows](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-windows-x64-setup.exe) | [ZIP](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-windows-x64.zip) |
| macOS 12+, Intel | [Install / maintain macOS Intel](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-macos-x64-maintenance.dmg) | [ZIP](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-macos-x64.zip) |
| macOS 12+, Apple Silicon | [Install / maintain macOS Apple Silicon](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-macos-arm64-maintenance.dmg) | [ZIP](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-macos-arm64.zip) |

[Release page](https://github.com/AndreyBrsv/Ashapp/releases/tag/v0.0.12) · [SHA256SUMS](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/SHA256SUMS) · [Matching source](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-source.zip)

Checksums for independently ready targets: [Windows](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-windows-x64-SHA256SUMS), [macOS Intel](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-macos-x64-SHA256SUMS), [macOS Apple Silicon](https://github.com/AndreyBrsv/Ashapp/releases/download/v0.0.12/Ashapp-v0.0.12-macos-arm64-SHA256SUMS).

**Windows:** run Setup and open Ashapp from the Start menu. For the portable ZIP instead, extract the entire archive and open `ashapp.exe`; keep its DLLs and `data` directory beside it. If a runtime is missing, install the official [Microsoft Visual C++ x64 Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe); see [Microsoft's documentation](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist). Flutter, Python, Docker and C++ Build Tools are not required on the computer running the packaged app. The Windows application is not Authenticode-signed.

**macOS:** open **Ashapp Setup** in the maintenance DMG, or extract the ZIP and move `Ashapp.app` to Applications. Plain PKGs remain available for older updaters. Choose your processor's download. This release uses ad-hoc signing, without Apple Developer ID signing or notarization. After verifying the download, follow [Apple's instructions for opening an unidentified developer's app](https://support.apple.com/en-us/102445) if Gatekeeper blocks it. Do not disable Gatekeeper globally. Keychain may request access again after replacing an ad-hoc build.

## Verify the download and source

Download the ZIP and its platform-specific checksum file from the same release. Combined `SHA256SUMS` is an alternative after every target finishes. In PowerShell, compare the output with its checksum line:

```powershell
Get-FileHash .\Ashapp-v0.0.12-windows-x64.zip -Algorithm SHA256
```

On macOS, put the ZIP and checksum file in one directory:

```sh
shasum -a 256 --check --ignore-missing Ashapp-v0.0.12-macos-arm64-SHA256SUMS
```

A checksum detects changed bytes. It does not independently prove the builder's identity or that the binary matches reviewed source. Each archive also has a `.build.json` release asset identifying its source commit, SDK, dependency lockfile hash, installer hash and CI run. Inspect that run and compare its commit with the release tag and matching source archive.

Public release builds publish [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) when the workflow supports them. Check the matching tag and build manifest. For a build that actually published an attestation, use the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify Ashapp-v0.0.12-windows-x64.zip --repo AndreyBrsv/Ashapp
```

Inspect the reported source commit and compare it with the release tag and build manifest. Public CI makes the build process inspectable; byte-for-byte reproducible builds are not claimed. GitHub workflow attestations require no private signing keys in this repository.

## Appearance

Select **Appearance** (the brightness icon in the top toolbar), then **System**, **Light** or **Dark**. Changes apply across all pages and server sessions without reconnecting. **System** follows the operating system appearance and is the default. The choice is saved locally in `appearance-settings.json`, separately from server profiles and credentials, and restored before the first application frame. A storage error leaves the last saved theme active and offers a retry.

### Compact workspace

Version v0.0.7 opens a compact window of approximately 520 × 760, adjusted to fit the display, with **Servers / Templates / Manage / Clients / Access** along the bottom. Widening the window moves these destinations to a sidebar. The server selector keeps the selected SSH address, port and session state visible on every page; switching servers preserves the other sessions. Forms and long pages scroll, including with larger text.

In **Clients**, **Copy Amnezia link** copies existing AmneziaWG access as `vpn://`; VLESS uses **Copy connection**. Neither action displays private keys. The original `.conf` remains available from **Get configuration**. Export dialogs offer copy icons, file saving and QR codes without a plaintext reveal step. VLESS format selection still controls which link or JSON is copied or saved; its QR always contains the original VLESS link. **Access** contains masked SSH/SOCKS5 credentials.

The shared [Ashapp logo and desktop icons](branding/README.md) use the warm Carbon A + small sh mark. Windows Setup uses the same mark as the app; macOS application icons come from the shared artwork. macOS Installer retains its standard system appearance.

## App updates

If the v0.0.8 Windows installer reports that the app constant is not initialized, install v0.0.12 manually from the link above. Existing local data is preserved; no uninstall or data reset is needed. CI now smoke-tests install/repair/uninstall in an isolated directory without starting the application.

**v0.0.8** adds **Restart and update**, Windows Setup maintenance choices and macOS maintenance disks. Updating preserves local data and reopens the installed app after success. System security/administrator prompts remain. The first update from v0.0.7 still uses its old installer handoff; use **Restart and update** in installed v0.0.9 to update to v0.0.12. The new source does not establish a completed real installation test.

Windows Setup offers **Update / repair** or **Uninstall**. macOS users can open **Ashapp Setup** in the maintenance DMG for the same choices; the PKG remains available for older updaters. An unchecked option also removes this user's local settings and protected passwords. Older installed versions need one update before full-data removal is available. VPS servers and files exported elsewhere remain unchanged. Installation/removal and credential-retention behavior still require manual end-to-end validation.

The **Check for updates** button in the top toolbar checks GitHub immediately. An exclamation badge marks an available update; select the button for details. When automatic checks are enabled, Ashapp checks at startup and then approximately once a day while running. Use the update dialog to change this preference or check manually. Downloads and installation always require your approval; checking does not send server addresses, SSH usernames, passwords or VPN keys to GitHub.

In published v0.0.7, choose **Download update**, then **Install update…**. Ashapp selects Windows x64, macOS Intel or macOS Apple Silicon for its running process, verifies the installer against GitHub's SHA-256 digest, `SHA256SUMS` and the source build manifest, and checks the file again before opening it. Interrupted, cancelled or invalid downloads are discarded. Installation is blocked while any server has an active task, including an unselected server. Once installation starts, all new server operations are paused.

For releases built with the per-platform publication workflow, each target has its own checksum file and becomes available as soon as its build and checks pass. Other targets may still be building. Older installed versions require all three targets and the combined `SHA256SUMS`, so their first update to a version with this workflow becomes available only after all builds finish. A release can remain incomplete if a build fails; a maintainer must investigate before attempting a retry.

Ashapp opens Windows Setup or macOS Installer and closes itself. Complete that system dialog, then reopen the app. Windows installs per user into `%LOCALAPPDATA%\Programs\Ashapp`, without an administrator prompt; macOS installs `/Applications/Ashapp.app` and may request administrator approval. Saved profiles, templates, trusted host keys and OS-vault entries are outside the application bundle and are preserved. Replacing an ad-hoc macOS build can prompt for Keychain access again. A previous portable Windows copy or a Mac copy outside Applications remains a separate, older copy; use the installed app after updating.

**Bootstrap and validation:** downloadable v0.0.3 has no updater or system installers. Install v0.0.4 or later manually once. From an installed v0.0.4 or v0.0.5, use **Check for updates** to download v0.0.7, finish Windows Setup/macOS Installer and reopen the installed app. Native CI compiles/packages the app and runs local tests; actual installer execution, macOS Installer sandbox handoff and OS-vault retention still need an end-to-end check. No claim of a completed end-to-end update is made.

Updates currently trust the public GitHub repository and HTTPS. Checksums detect altered bytes; they are not independent publisher signatures. Windows packages remain unsigned and macOS packages are not Developer ID-signed/notarized. OS security confirmation may be required. Published v0.0.7 does not silently install. The v0.0.8 background flow also preserves system security prompts; neither implements independently signed/offline update feeds. See [update behavior and release requirements](docs/UPDATES.md).

## Configure a VPS

Use an already-created VPS with a public IPv4 address, SSH access, systemd and **Ubuntu 22.04/24.04 or Debian 12**. Setup detects the supported distribution and package architecture. AmneziaWG requires full virtualization such as KVM, supported kernel headers and a compatible kernel. VLESS installation supports Linux x86_64 and aarch64. Restricted containers and provider-specific kernels may prevent installation. A 2-vCPU / 2-GB VPS is the intended starting point; CPU use depends on traffic and hardware.

1. Choose **Set up a server**, then manual answers or a saved template.
2. Enter its IP, SSH port and **current** SSH credentials. Template passwords describe account changes after login; they are not the initial login password. Check the first SSH fingerprint against the provider's console. A changed fingerprint requires explicit review before replacing trust for that endpoint.
3. Choose whether to rotate the root password, create an administrator, add a public SSH key, disable root SSH, block IPv4 ping and upgrade packages. Administrators receive passwordless sudo automatically; the review explains this before execution.
4. Select AmneziaWG, VLESS + Reality, both or neither; SOCKS5 is independent. Defaults: AmneziaWG UDP `585`, DNS `1.1.1.1`, VLESS TCP `443`, SOCKS5 TCP `1080`. VLESS, SSH and SOCKS5 need different TCP ports; TCP and UDP can share a number. VLESS also asks for a public TLS 1.3/HTTP2 Reality SNI and client fingerprint.
5. Enter first-device names separately for each protocol, review the answers and run setup. AmneziaWG devices get individual keys; VLESS devices get individual UUIDs and Short IDs. Root SSH is disabled only after an independent administrator SSH login and sudo check succeeds.
6. The result shows IP, account name, masked password and SOCKS5 credentials if installed. Copy or reveal credentials explicitly. Export AmneziaWG `.conf` files/QR codes, or VLESS links/QR codes and Xray/sing-box JSON, into a compatible client.

### Installation state, recovery and diagnostics

**Server activity** shows bounded, redacted output for the captured SSH session, including action names, exit status and completed/failed steps. Output stays in memory unless explicitly copied. This read-only console does not accept arbitrary shell commands.

The server also keeps a root-private installation ledger under `/var/lib/ashapp/lifecycle/`. It records allowlisted non-secret desired settings, action identifiers and step outcomes, without passwords, SSH usernames, device names, keys, exported configurations or raw command output. It survives app restarts. Recorded work is not proof of health: diagnostics inspect actual state.

Interrupted setup can be resumed explicitly from its saved plan instead of replaying completed account/password changes. Recovery answers stay in the local OS credential vault and are matched to the server-side run. A computer without those protected answers must review and supply them again. An interrupted step may have partial effects; package upgrades and committed account changes remain applied.

Diagnostics compare requested settings with actual VPN services, kernel mode, SSH policy, ping rules and owned protection. Results distinguish failures, warnings and unknown state. They cannot prove provider-firewall reachability or adoption by another VPN application. A server without VPN can open the full setup wizard to select protocols.

### Reset Ashapp changes

Reset first presents a reviewable removal plan. It removes only positively identified Ashapp-owned VPN/SOCKS5 deployments and restores captured SSH/security/ping settings where ownership and unchanged evidence can be verified. Removing a deployment revokes its device access and removes its protected server-side exports. Unknown deployments, external edits or a missing trustworthy baseline can require manual recovery rather than being overwritten.

**Reset is not an OS reinstall.** Administrator accounts, current passwords, upgraded packages, Docker itself, external services and unrelated policy remain. The original root password cannot be recovered. Access-affecting restoration uses staged independent confirmation and recovery. Provider firewall rules and client files exported elsewhere are outside reset. Local application uninstall is separate and never resets a VPS.

Open the selected AmneziaWG UDP, VLESS TCP and SOCKS5 TCP ports in the hosting provider's firewall panel. VLESS adds a dedicated persistent host INPUT rule without replacing existing rules. Keep SSH accessible. A ping timeout is expected when ping blocking is selected. Ashapp does not edit the provider's firewall panel.

If you defer installation, configure VPN yourself in your preferred app. New AmneziaWG setups offer **Shared kernel - Experimental**, which creates a real container on a fresh x86_64 VPS and retains a verified kernel data plane. **Official discovery/adoption may not work with your AmneziaVPN version.** Existing deployments and saved template choices are preserved; legacy templates without the deployment field retain **Host kernel**. In AmneziaVPN 5.0.3.0, **Self-hosted VPN → Choose Installation Type** appears before discovery: **Automatic → Continue** selects `amnezia-awg2` and checks for the running installation before deciding whether installation is needed. The page alone is not a failed-discovery result. Its [discovery code](https://github.com/amnezia-vpn/amnezia-client/blob/de93650a90739b87bb47a632872ea9d0adc9412f/client/core/controllers/selfhosted/installController.cpp) does not adopt host services or discover stopped containers. For **Host kernel**, use **+** and import the client key or `.conf` from Ashapp's **Clients**. Client links alone never grant administrator access. In **Clients**, **Copy Amnezia link** and protected `.vpn` export support one IPv4 client address and one or two IPv4 DNS resolvers. Unsupported configurations retain their original `.conf` and native QR. See [shared management and verification limits](docs/AMNEZIA_SHARED.md). Client software is available from the [official Amnezia downloads](https://amnezia.org/downloads).

**Existing AmneziaVPN servers:** **VPN clients** supports the official `amnezia-awg` and `amnezia-awg2` containers. Choose the VPN installation when creating a client, enter its name and DNS address, then export its private configuration as a file, clipboard text or QR code. Existing peers can be renamed or revoked by their public key. Both clientsTable formats are preserved, including unrelated metadata, so AmneziaVPN can read the saved names. Host kernel clients can also be renamed. A duplicate name on another server or in another container is a different client.

**Reopen an existing key and QR:** select **Get configuration** or **Show QR code** on a client. Copy the complete configuration or explicitly copy its private key; the public key has a separate copy action. These actions read the saved original config and never create or rotate a peer key. A large config that does not fit in a QR can still be copied or saved as a file.

For an older client created outside Ashapp, choose **Import existing .conf**, select its original UTF-8 file or paste its contents, then save the protected copy. Imports start hidden. The backend verifies the private/public identity, server key, PSK, addresses and required obfuscation settings. Executable wg-quick hooks and ambiguous configs are rejected. **Replace saved copy** is an explicit opt-in; it changes only the protected stored file, never VPN access. After importing, the same original key/config is available on later opens, including after restarting Ashapp. This import accepts `.conf` data; export `vpn://` links to `.conf` in the original app first. A public key cannot reconstruct a lost original private key.

AmneziaWG client updates do not restart that VPN or replace its installation. They compare saved file hashes before applying a change, use a private per-container transaction lock and change only the selected live peer. Avoid editing the same VPN concurrently in AmneziaVPN and Ashapp: the other application does not share Ashapp's lock. Ordinary failures restore the previous configuration, metadata and affected live peer. If an interrupted transaction or failed rollback leaves an uncertain state, private backups and the lock remain under `/opt/amnezia/awg`; inspect the server before removing that lock or retrying. Do not share those backups: they contain keys.

New and imported container-client private configurations are stored on the server under root-only `/var/lib/ashapp/clients/amnezia/`, separated by container and public-key hash. Host copies use the protected host-client directory. Existing clients whose original private key is unavailable can still be renamed or revoked, but their configuration cannot be recovered or exported. No existing key is silently replaced. Ashapp provides service controls for its owned shared kernel container; use AmneziaVPN for external container service controls. Setup preserves external deployments and refuses migration or replacement. Stopped containers and read failures show an explanation instead of a misleading empty list. Local fixtures cover client-management/import/key/QR paths. Earlier development experiments do not validate current changes; official GUI adoption and external traffic remain separate checks.

Host clients remain visible when the VPN is stopped, including peers without installer-specific markers. Management actions are enabled only for supported clients. A missing private client configuration cannot be reconstructed from public peer data.

## VLESS and client exports

For **VLESS + Reality + XTLS Vision**, select the protocol in setup or a template, then use **VPN clients → Create client**. Choose the protocol/installation for each device. **Get configuration** offers a standard `vless://` link, Xray JSON and sing-box JSON; copy or save the selected format. **Show QR code** always encodes the same existing VLESS link, including when JSON is selected. No UUID or Reality key is rotated by exporting. Private server keys and administrative data are never included.

VLESS runs in `ashapp-vless.service` using checksum-pinned **sing-box 1.14.4**, separately from AmneziaWG. Client changes briefly restart only VLESS connections; AmneziaWG stays running. Existing third-party Xray/sing-box panels are not adopted. The JSON exports start a local proxy on `127.0.0.1:10808`, not an OS-wide VPN. Local traffic checks passed with **Xray 26.10.31** and **sing-box 1.14.4** clients, plus independent QR decoding and per-device revocation checks. Fresh Linux/systemd provisioning and two real VPN protocols running together on a VPS remain unverified. See [VLESS setup, compatibility and validation](docs/VLESS.md).

## Templates and multiple servers

Manual setup and templates share the **same questions and execution path**. Templates prefill passwords, public SSH key, account/security choices, package upgrades, AmneziaWG port/DNS, VLESS port/SNI/fingerprint, optional SOCKS5 credentials and separate per-protocol client names. Every answer remains editable before applying it to a new VPS. Templates are local to the computer. Editing updates the existing template; duplication is a separate action.

If the OS credential store is locked while removing unused template answers, Ashapp keeps only their opaque references in a cleanup queue. Unlock the store and select **Retry protected cleanup**; pending cleanup also retries after restarting the app. Passwords never enter that queue.

Use **Connect to existing** for another connection. The server menu at the top switches sessions while preserving other servers' credentials, client lists and tasks. Each endpoint has its own command queue. A failure or disconnect affects that endpoint only.

Management includes service status, VPN-client creation/revocation/export, service start/stop/restart, administrator creation, root-password rotation, ping policy, Linux-account inspection, saved credentials, SOCKS5 replacement and reboot. Lost private client files cannot be reconstructed from public keys: revoke the old client and create another.

Repeated setup preserves existing VPN/SOCKS5 configurations and adds missing requested clients. SOCKS5 replacement is explicit and checks authentication before removing the previous container. Failed initial VPN activation removes its new partial configuration so setup can be retried. Completed package upgrades and account changes remain applied after a later step fails; inspect progress and refresh status before retrying.

## Server security controls

Use **Manage → Security → Run diagnostics** for the selected endpoint. Controls are drafts until **Review and apply changes** is confirmed. New setup/templates offer SSH Fail2ban and firewall configuration; legacy templates acquire neither automatically. Automatic OS security updates and disabling all password SSH login start off. Setup's unselected choices preserve existing policy; explicit management changes can turn Ashapp protection on or off. Unchecking a managed option stages its inverse while unrelated external policy remains.

SSH keys can be generated separately per server or imported. A fresh key login and sudo check must succeed and the key must be saved in the OS vault before disabling password login. Private key text stays hidden; **Copy SSH private key** is explicit. Root SSH denial is a separate choice. Unsupported conditional SSH policy requires manual review.

Security changes are staged with a 180-second deadline. A separate authenticated SSH connection confirms them. Without confirmation, a server timer attempts recovery; a boot recovery unit also handles an interrupted reboot. Concurrent external edits can require manual recovery. Package installation is not rolled back. Keep the provider console available. Firewall protection uses owned IPv4/IPv6 rules, preserving existing ports/policy; active external UFW/firewalld, restrictive existing INPUT base policies and unsupported Docker backends require manual review. Diagnostics show listening ports, not proof of Internet reachability.

SOCKS5 defaults to its existing public mode. **Private · SSH tunnel** requires stable Docker Engine 28.0.0 or newer on the server and publishes on server loopback; older localhost publications have a documented Docker exposure issue. Unsupported existing private services remain stoppable or explicitly replaceable. Fresh supported servers can receive Docker from its authenticated, distribution-specific APT repository. An existing incompatible or unavailable daemon requires manual review; Ashapp does not replace, upgrade or restart a shared runtime automatically. Start its tunnel in Manage, then use the displayed **127.0.0.1:local-port** and proxy credentials in your client; keep Ashapp connected. This is a local SSH forward, not adoption by AmneziaVPN or a VPN-only listener. Stop private tunnels before installing an app update. See [Server security](docs/SERVER_SECURITY.md) for ownership, Fail2ban, OS updates and validation limits.

Changing server-side SOCKS5 credentials does not rewrite profiles already cached by another application. Refresh/re-import its profile or update the saved username/password explicitly. Ashapp does not control another application's local settings.

## Credentials and security limits

**Security fixes retained from v0.0.4:** Debian package trust uses a full fingerprint and a dedicated repository keyring. Ashapp refuses automatic root-SSH disabling when retained `Match` policy needs manual review, replaces private exports using fresh protected files, and corrects VLESS service-directory permissions under a restrictive umask. These changes do not apply to older v0.0.3 binaries. Native tests do not replace sandboxed macOS save-dialog validation. Conditional SSH policies still require manual review.

- Authorized saved passwords use the operating system's protected storage and macOS login Keychain. There is no plaintext fallback. Passwords start masked and are hidden again when the displayed credential changes.
- Server-profile JSON contains only IP addresses and SSH ports. Template JSON contains non-secret choices and a random reference to protected answers. Trusted SSH fingerprints are separate. Passwords and private keys do not belong in those JSON files.
- Passwords travel through encrypted SSH stdin, not shell arguments. Server logs have restrictive permissions and do not intentionally print passwords or private VPN keys. Copy/export actions deliberately disclose secrets: protect your clipboard and files. macOS exports enforce owner-only permissions before writing private bytes.
- The AmneziaWG tunnel and VLESS server listener are **IPv4-only**. AmneziaWG does not protect client IPv6 traffic. VLESS JSON exports start a local proxy rather than an OS-wide tunnel; routing and leak protection depend on the chosen client. SOCKS5 password authentication is **not encrypted transport**; use it with an appropriate protected connection or application protocol.
- New AmneziaWG installations use the kernel module only, with shared container mode selected initially for new setups and templates; host mode remains available explicitly. Saved choices and legacy host-mode templates are preserved, without migrating existing servers. Experimental shared mode removes the Go fallback and verifies the real interface, startup guard and process list before reporting kernel readiness. This does not prove official GUI adoption. Ashapp also manages clients in existing official AmneziaVPN containers and installs optional SOCKS5 in Docker. MTProto is outside the product scope. Package repositories, the checksum-pinned installer and digest-pinned container images remain external supply-chain dependencies.
- A compromised local account, OS credential store or root server is outside the app's protection boundary. Keep the provider's recovery console available before changing SSH access.

Never put credentials, private keys, client configurations or unredacted logs in Git or issues. `.gitignore` excludes common secret, profile, export, cache and build paths. CI uses a checksum-pinned Gitleaks scanner on publishable source and Git history. Scanning reduces risk; it cannot guarantee recognition of every secret format.

## Build from source

Use [Flutter 3.47.9](https://docs.flutter.dev/install/archive), Dart 3.13.x and the committed `flutter/pubspec.lock`. Build each desktop target on its corresponding OS.

**Windows:** install [Git](https://git-scm.com/downloads/win), Flutter and [Visual Studio / Build Tools](https://visualstudio.microsoft.com/downloads/) with **Desktop development with C++**, a Windows SDK and **C++ ATL for the installed MSVC toolset (x86 & x64)**. The secure-storage plugin requires ATL. Enable Developer Mode for Flutter's plugin symlinks. Follow [Flutter's Windows guide](https://docs.flutter.dev/platform-integration/windows/setup) and resolve `flutter doctor -v` errors. These development tools are separate from the VC++ Runtime needed by a downloaded app.

**macOS:** install Flutter, [Xcode](https://developer.apple.com/xcode/) and command-line tools. The project uses Swift Package Manager. If Flutter reports a CocoaPods dependency, follow the [macOS setup guide](https://docs.flutter.dev/platform-integration/macos/setup) and [CocoaPods installation instructions](https://guides.cocoapods.org/using/getting-started.html). See [Flutter's macOS release guide](https://docs.flutter.dev/deployment/macos) for distribution signing.

```sh
git clone https://github.com/AndreyBrsv/Ashapp.git
cd Ashapp/flutter
flutter pub get --enforce-lockfile
flutter analyze --no-pub
flutter test --no-pub
flutter run -d windows
# On a Mac instead:
flutter run -d macos
```

For release builds use `flutter build windows --release` or `flutter build macos --release`. Copy the complete Windows release directory or macOS `.app`. CI creates separate Intel and Apple Silicon archives and checks their architectures.

Packaging the new Windows Setup executable also requires [Inno Setup 6](https://jrsoftware.org/isinfo.php), available on the Windows CI image. Set `INNO_ISCC` to `ISCC.exe` if it is outside the usual Program Files directory. macOS packaging uses `xcrun swiftc`, `codesign`, `pkgbuild` and `hdiutil`. These tools are needed only to build release installers, not to run Ashapp. Each platform passes its source/checksum gate before its assets publish. Combined checksums wait for all three targets.

The Apple Silicon archive is cross-compiled with Xcode on an Intel Mac runner because hosted ARM runners can be unavailable. CI checks the executable and every embedded Mach-O dependency for arm64 support; tests execute on the Intel host. Physical Apple Silicon runtime validation is still pending. Each build manifest records the build/test host architecture.

Server tests need [Python 3.13](https://www.python.org/downloads/) and Bash (included with Git for Windows). From the repository root:

```sh
python -m unittest discover -s tests -v
bash -n server/remote.sh
bash -n vendor/amneziawg-install.sh
python tool/check_secrets.py
```

Automated tests use fake SSH/Docker and temporary files without modifying a VPS. Current validation must be reported with the release run; older test counts and successful experiments do not establish the latest source's behavior. Real recovery/reset, provider reachability, official GUI adoption, reboot behavior, physical Apple Silicon and end-to-end update/credential retention require separate checks.

## Repository and licensing

`flutter/` contains the app and native runners; `server/` contains privileged helpers; `tests/` contains server checks; `tool/` and `.github/workflows/` package and verify releases. Scripts in `flutter/assets/` must exactly match their sources.

The [Varckin installer](https://github.com/Varckin/amneziawg-install) retains its [separate MIT notice](vendor/LICENSE.Varckin) and SHA-256 `10c9ef9b3b4e9ee4838c06fb8fe89a512a65149f68830dc87fe90f437d2accd4`. Ashapp verifies it before invoking its kernel package routine. Dependencies retain their own licenses; Flutter includes dependency notices in the application bundle.
