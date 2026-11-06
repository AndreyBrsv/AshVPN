Ashapp v0.0.12

Set up a VPS from reusable answers, then inspect and manage the actual result. This release adds a root-private server installation ledger, explicit recovery of interrupted setup using protected local answers, deeper diagnostic checks and a reviewed reset of positively identified Ashapp-owned services/settings. Reset retains administrator accounts, current passwords, packages and unrelated services; it is not an OS reinstall.

Setup and management gain a bounded Server activity console with action names, exit status and redacted output. SSH errors distinguish changed server keys from rejected authentication. Current SSH credentials stay separate from template passwords used to configure accounts after login. Package upgrades prepare SSH before inspection, and security dependencies are prepared before the final listener snapshot.

Existing AmneziaWG devices can export AmneziaVPN vpn:// links and protected .vpn files alongside their original .conf and QR. Shared kernel-container management is explicitly experimental: official discovery/adoption may not work with your client version. Use one manager at a time. Host kernel mode and existing deployments remain supported and are never migrated silently. Client links do not grant administrator management access.

Fresh Docker setup detects Debian 12 or Ubuntu 22.04/24.04 and uses an authenticated distribution-specific repository. Existing runtimes are preserved. Private SOCKS5 still needs a supported stable daemon and loopback publication. Server credential changes do not automatically rewrite profiles cached in another client application.

Compact-window checks cover enlarged text, scrolling dialogs, long device names and reachable actions. Per-platform publication, update badges, verified downloads and installer maintenance remain available.

Use Check for updates, Download update, then Restart and update. Earlier updaters may wait for all three platform builds. Finish all server tasks and close private tunnels first. System security/administrator prompts may remain.

Windows and both macOS targets publish independently only after native validation. Earlier updaters may wait for all targets and combined checksums. Windows packages are unsigned; macOS uses ad-hoc signing without notarization. Apple Silicon may be cross-compiled/tested on an Intel host.

Fixture tests and native builds do not establish live recovery/reset, provider reachability, official cross-manager GUI adoption, reboot recovery or end-to-end installer/credential retention. The owner will test a separate VPS. Earlier development experiments are not validation of the latest changes.
