# Application updates

Introduced in **v0.0.4**. Published v0.0.3 does not contain it. The first updater-enabled release must be installed manually; an old binary cannot acquire updater code by checking GitHub.

The background-maintenance behavior documented below is **v0.0.8 source**. Published v0.0.7 and earlier still open the interactive system installer. Publication requires all native targets and verified assets; source changes alone do not establish publication.

## User flow

1. Open **App updates** in the toolbar. Background checks run at most daily while the app is open, plus a due check at launch. Disable **Check automatically** to opt out. **Check now** remains available.
2. A stable newer release shows its version and plain-text release notes. A badge remains in the toolbar. Checking never installs or downloads executable packages automatically.
3. Choose **Download update**. Progress and cancellation are available. Downloading can continue while managing servers or after dismissing the dialog.
4. Choose **Restart and update** and confirm. Finish tasks on every server first. New operations on existing and newly added server sessions are gated during installation handoff.
5. Choose **Restart and update**. Windows starts Setup with fixed silent/no-reboot/no-force-close switches; it waits up to 60 seconds for the application mutex, replaces files and reopens Ashapp on success. macOS stages its bundled Cocoa helper outside the application, waits for helper validation/readiness, then quits. The helper waits for the old process, rehashes the PKG, requests system administrator authorization, installs it and reopens Ashapp. A launch/readiness failure keeps the app open. A successful handoff is not proof of installation success.

Windows Setup installs the whole bundle to the current user's Programs directory and creates a Start menu entry. It does not require elevation, force-close running applications or delete user profiles. A named mutex makes Setup wait for Ashapp to close. Background updates require the fixed per-user installed copy; portable copies are refused.

macOS Installer replaces `/Applications/Ashapp.app`, with strict bundle identity/version checks and relocation disabled. The PKG contains no privileged install scripts or daemon. The bundled, separately ad-hoc-signed maintenance helper runs outside App Sandbox through Launch Services and invokes only the local system installer with an app-owned command, quoted local path and system authorization. It has no network or vault access. Copies outside Applications are refused for background updates. The Intel build running under Rosetta selects Intel; the native Apple Silicon build selects arm64.

## Maintenance and uninstall

Windows Setup detects its existing fixed per-user installation and offers Update / repair or Uninstall. The additional macOS `Ashapp-v<version>-<target>-maintenance.dmg` contains Ashapp Setup and the checksum-bound PKG: install/update, uninstall or cancel. Plain PKGs remain available for older updater compatibility and do not offer uninstall. The DMGs participate in source manifests, SHA256SUMS and provenance publication.

Uninstall defaults to keeping local data. A separate unchecked choice removes saved servers, templates, preferences, trusted host keys, cached updates and Ashapp's vault entries. The installed app performs cleanup under its own protected-storage identity, only after final confirmation and while other sessions are closed. It deletes only `ashapp.` entries, never all entries in a shared Keychain service. Vault failures abort removal before deleting the executable. Earlier app versions do not implement cleanup, so full-data removal is disabled until one update has been installed. Exported files and all remote VPS state remain untouched. macOS removes only the fixed identity-checked Applications bundle; receipts and OS-managed caches can remain.

Server profiles, template metadata, trusted SSH keys and OS-vault entries stay in their existing support locations. The update cache contains only public release files. `update-settings.json` stores the automatic-check switch and last successful check timestamp. Passwords, SSH usernames, server IPs and VPN keys are never sent in update requests. GitHub still receives ordinary network metadata, such as the requester's IP address.

## Verification and trust

The app requests the fixed repository's public `releases/latest` endpoint, without a GitHub token. It accepts numeric stable versions and never offers a downgrade. It requires all three platform installers and build manifests, so partially uploaded releases are refused.

For the selected platform it verifies:

- Exact expected asset name and HTTPS download URL; uploaded state, positive bounded length and GitHub SHA-256 digest.
- GitHub digests and lengths for `SHA256SUMS` and the platform `.build.json`.
- Installer and build-manifest entries in `SHA256SUMS`, without duplicate or path-bearing names.
- Matching version, platform, source commit format, installer name, size and hash in the build manifest.
- Exact installer length and streaming SHA-256, then a second hash immediately before native launch.

Redirects are restricted to HTTPS on known GitHub hosts. Metadata, response idle time and total download duration are bounded. Errors never fall back to unchecked execution. Release notes are plain text. The client does not download or execute updater scripts. It opens only the selected local `.exe`/`.pkg` from its update cache.

Native handoff retains internet-download provenance: Windows Attachment Services applies Mark of the Web/attachment policy; macOS sets documented quarantine properties before handing the PKG to maintenance; the elevated staging copy retains download metadata. A policy/metadata failure stops handoff. The app never removes these origin markers to bypass OS checks.

This trust model depends on GitHub repository/release integrity and HTTPS. The digest and checksum file come from the same publisher; they do not protect against a compromised release account. Artifact attestations are an additional user-verifiable source/CI link when actually published, not an independent check performed by this updater. There is currently no pinned update-signing public key or offline signature verification. Adding signed release metadata would require protected CI signing credentials and a planned key-rotation policy.

The Windows app/Setup are unsigned. macOS uses an ad-hoc app signature and an unsigned, non-notarized installer. OS security prompts remain in place. Ad-hoc replacement can request Keychain access again. Do not weaken the app's code-hash requirement or disable Gatekeeper to hide these limits.

## Release contract

Every new version needs a new source commit, a higher numeric app version/build number and a new tag. Never republish v0.0.3 with these changes. Keep earlier releases and tags.

`tool/package_release.py` builds the complete native ZIP and system installer together, then records their hashes, lengths and source identity in the platform `.build.json`. macOS also records the maintenance DMG. Windows needs Inno Setup 6 (`INNO_ISCC` can select its path); macOS uses `xcrun swiftc`, `codesign`, `pkgbuild` and `hdiutil`. Maintenance helpers contain no private signing keys. Installers include the application's license notices.

`tool/prepare_release.py` refuses mixed commits, missing platforms, modified archives/installers and unexpected release-output files. Its `SHA256SUMS` covers all ZIPs, installers, manifests and the source ZIP. The publish job waits for all three native jobs and publishes the release only after uploading the complete set. New public builds can attest ZIPs/installers through the pinned GitHub action. Update publication still requires the owner's explicit release instruction and manual `workflow_dispatch` publication; ordinary commits do not publish.

Expected installer names:

| Platform | Asset |
| --- | --- |
| Windows x64 | `Ashapp-v<version>-windows-x64-setup.exe` |
| macOS Intel | `Ashapp-v<version>-macos-x64-setup.pkg` |
| macOS Apple Silicon | `Ashapp-v<version>-macos-arm64-setup.pkg` |

## Validation limits

Unit/widget tests use synthetic release bytes and fake native launchers. They exercise platform selection, bad metadata/digests, duplicate/partial assets, cancellation, preferences, corruption after download, confirmation and all-server operation gates. Python tests exercise installer arguments, macOS payload boundaries and publication checks without installing software. Windows app compilation is available locally.

Before claiming a working end-to-end update, validate Windows Setup compilation and installation in a disposable user profile, a second-version update, mutex behavior and credential retention. macOS needs native compilation/XCTest and the sandboxed-app-to-maintenance-helper handoff on Intel and Apple Silicon, followed by actual installation and Keychain checks. No real server or existing user installation should be changed by unit tests.
