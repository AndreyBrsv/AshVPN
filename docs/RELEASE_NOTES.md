Ashapp v0.0.9 fixes Windows installer startup and removes the duplicate in-app logo and title.

- Fixes the v0.0.8 Windows installer crash caused by expanding the destination constant before wizard initialization. Native CI now installs, repairs and uninstalls into an isolated disposable directory without running Ashapp or accessing saved credentials.
- The native system title bar remains; the inner toolbar keeps update and appearance actions without repeating the logo/name.
- The toolbar is more compact. Server selection, navigation, larger-text layouts and independent server sessions are retained.
- Background updates, installer update/uninstall choices and optional local-data removal are unchanged from v0.0.8. The Carbon app/installer icon assets are unchanged.

If v0.0.8 installation failed, download and run the v0.0.9 installer manually; you do not need to uninstall or clear data first. If v0.0.8 is installed, choose Check for updates, Download update, then Restart and update. Finish tasks on all servers, close private tunnels and resolve pending security confirmations first. The app should reopen as v0.0.9 after successful installation. System security/administrator prompts may remain. Versions through v0.0.7 still use the interactive installer.

Validation: native CI must pass all three targets before publication; manifests, source archive, SHA256SUMS and provenance accompany the release. macOS arm64 is cross-compiled/tested on an Intel host. Actual background installation/relaunch, removal, OS-vault retention and physical Apple Silicon behavior require manual validation. No real VPS is changed by release tests. Windows remains unsigned; macOS is ad-hoc signed and not notarized. Checksums/provenance do not prove independent publisher signing, reproducibility or absence of defects.
