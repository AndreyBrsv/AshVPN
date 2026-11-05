Ashapp v0.0.11

Windows and each macOS build can now publish independently, with platform-specific checksums and source identity. Automatic checks run at launch and keep a visible update badge when an update is available.

The application review fixes preserve active runtime-only AmneziaWG peers, reject conflicting external firewall policy, verify owned protection rules, bound SSH preparation and command execution, retain concurrent VLESS edits, validate client endpoint ports and report export-cleanup failures separately from revocation. Password changes occur after account preparation. Ping controls remove only marked Ashapp rules. Legacy unmarked ping plugins require manual review. macOS Release includes permission for loopback SOCKS listeners.

Use Check for updates, Download update, then Restart and update. Earlier updaters may wait for all three platform builds. Finish all server tasks and close private tunnels first. System security/administrator prompts may remain.

Native CI, isolated Windows install/repair/uninstall, hashes and provenance must pass before publication. Real background installation/relaunch and credential retention are not established by these checks; the owner will test them manually. macOS arm64 is cross-compiled on Intel; physical Apple Silicon remains unverified. Windows is unsigned and macOS is ad-hoc signed without notarization.
