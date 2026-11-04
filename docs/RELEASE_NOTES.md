some testings

Version-only release for testing the v0.0.9 to v0.0.10 update. Application behavior and the Windows installer startup fix are unchanged.

In installed v0.0.9, choose Check for updates, Download update, then Restart and update. Finish all server tasks and close private tunnels first. System security/administrator prompts may remain.

Native CI, isolated Windows install/repair/uninstall, hashes and provenance must pass before publication. Real background installation/relaunch and credential retention are not established by these checks; the owner will test them manually. macOS arm64 is cross-compiled on Intel; physical Apple Silicon remains unverified. Windows is unsigned and macOS is ad-hoc signed without notarization.
