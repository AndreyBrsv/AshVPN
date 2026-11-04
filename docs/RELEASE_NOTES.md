Ashapp v0.0.8 adds background updates and installation maintenance.

- Download an update, then choose Restart and update. All server tasks, private tunnels and pending security changes must be idle. Windows uses per-user silent Setup; macOS uses a bundled maintenance helper and system administrator authorization. Successful installation reopens Ashapp and preserves local data.
- Windows Setup detects the existing installation and offers Update / repair or Uninstall. macOS maintenance DMGs provide an Ashapp Setup window with the same choices. Plain PKGs remain available for older updaters.
- An unchecked full-removal option deletes this user's local servers, templates, preferences and Ashapp vault entries. Other apps' vault entries, exported files and remote VPS servers are not removed. A protected-storage failure aborts full removal. Older binaries must be updated once before full-data removal is available.
- Downloads retain checksum/source-manifest validation and OS download policy. Windows rehashes the locked file before launch; macOS rehashes an elevated private staging copy after authorization. No update-signing private keys are embedded.

Updating from v0.0.7 still opens its ordinary system installer: that installed binary cannot use the new updater yet. Install v0.0.8, then use the next release to test Restart and update. The duplicate-logo/header change is intentionally deferred to v0.0.9; v0.0.8 keeps the previous appearance.

Native CI must pass Windows, Intel macOS and Apple Silicon cross-compilation before publication. macOS arm64 tests run on the Intel build host. Actual installer execution, background update/relaunch, removal, Keychain/vault retention and physical Apple Silicon behavior require manual validation. Windows remains unsigned; macOS uses ad-hoc signing without notarization. OS confirmation may remain. Hashes and provenance are not independent update signatures or proof of reproducible/defect-free builds.
