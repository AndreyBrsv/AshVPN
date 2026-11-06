Ashapp v0.0.14

Fix the blank Manage page after applying changes to an existing server. Installation-journal expansion state now has separate, server-scoped storage keys instead of colliding with the page scroll offset. Compact-window and multi-server regressions cover the security confirmation and journal refresh flow.

Firewall review includes fixed public bindings of stopped Docker containers and allocated runtime ports of running containers. Reviewed public Docker ports are retained in both host INPUT and Docker forwarding paths, including userland-proxy traffic. Loopback-only private SOCKS5 publications remain excluded from public allows. Unknown or unallocated publications prevent enabling protection; explicitly removing owned protection remains possible when Docker inspection is unavailable, with an unknown-status warning and existing ownership/SSH guards.

Use Manage / Security / Refresh firewall ports after installing or changing a protocol through AmneziaVPN. The action obtains a fresh port preview and requires confirmation. The firewall checkbox controls saved policy; effective rule verification appears separately so drifted protection can be repaired or disabled. A successful SSH confirmation does not prove VPN traffic or provider reachability.

SOCKS5 details now follow the actual server container and published port. Access reads capture the container ID and reject concurrent replacement, stop or publication changes instead of combining old credentials with a new endpoint. Refresh and diagnostics discard stale displayed credentials without fetching secrets automatically. Private tunnels remain only when fresh evidence still identifies the same running private target; changed or unknown targets close.

Manage shows the server proxy and local SSH-tunnel endpoints separately. Ashapp and AmneziaVPN use the same named SOCKS5 service, but AmneziaVPN keeps its own local cached credentials: update or rediscover that saved connection after changing server access. Replace SOCKS5 proxy explicitly recreates the existing container, including an official installation; it is not just a cached-password edit.

Templates, installation recovery, diagnostics, reviewed reset, existing Amnezia links and per-device exports remain available. Shared AmneziaVPN kernel-container management remains experimental; official discovery/adoption may not work with your client version. Edit from one manager at a time. Existing host deployments and external policy are preserved.

Use Check for updates, Download update, then Restart and update. Finish server tasks and close private tunnels first. Windows and each macOS target publish independently after their own native checks; older updaters may wait for all targets and combined SHA256SUMS. The release page is authoritative for uploaded assets.

Windows packages are unsigned. macOS uses ad-hoc signing without notarization; Apple Silicon may be cross-compiled and tested on an Intel host. System security/administrator prompts remain. Checksums and GitHub provenance link downloaded artifacts to the release source, without claiming byte-for-byte reproducible builds or defect-free code.

Local fixtures and native builds do not establish the exact reported live-VPS failure, external VPN traffic, official Amnezia GUI adoption, reboot recovery, physical Apple Silicon behavior or end-to-end installer/update credential retention. The owner will test the VPS; no live server was changed while preparing these maintenance fixes.
