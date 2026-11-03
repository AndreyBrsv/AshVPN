# VLESS + Reality + XTLS Vision

Available since Ashapp v0.0.3. See the [release downloads and launch instructions](../README.md#download-v004). Native builds and local protocol checks do not establish real-VPS provisioning compatibility.

## Setup and device management

Choose **Install VLESS + Reality** in the same setup wizard used by manual setup and templates. It is independent of **Install AmneziaWG** and **Install SOCKS5**. Both VPN protocols can be selected. Enter the TCP port (default 443), Reality SNI/target hostname and client TLS fingerprint (default `chrome`). The server probes the public target with certificate verification, TLS 1.3 and HTTP/2 before installation. Target availability and suitability depend on the VPS network; this does not guarantee resistance to blocking.

Templates retain these non-secret choices and separate device-name lists for each protocol. UUIDs and generated Reality keys are never template answers. The same device name in two protocols or on two servers identifies different access. Server profiles still contain only IP and SSH port.

The app installs the official **sing-box 1.14.4** Linux x86_64/aarch64 binary after checking a source-pinned SHA-256 digest. It runs as an unprivileged system account with a dedicated systemd service, restrictive filesystem access and only the capability needed to bind a privileged port. No Docker VPN is installed. An existing third-party proxy or conflicting port is not replaced.

Each VLESS device receives a random UUID and Short ID. Create, rename, revoke and reopen exports in **VPN clients**. Operations use the original SSH endpoint (including SSH port), protocol source and UUID, rather than the current selection or display name. Revocation removes the UUID from the server configuration. Repeated setup preserves current settings/keys and adds missing device names.

Configuration changes are validated with `sing-box check` before application. Applying them briefly restarts **only the VLESS service**. Other VLESS devices retain credentials but reconnect; AmneziaWG is not restarted. Editing clients while VLESS is stopped preserves its stopped state. Ordinary application failures restore the previous saved configuration and running state. Interrupted/uncertain transactions retain protected recovery files and block further changes; inspect the service before removing any pending marker. Completed package/account steps are not rolled back with a later VPN failure.

## Export formats

One immutable `VlessConnection` supplies all formats. Each preserves UUID, server address/port, SNI, Reality public key, Short ID, fingerprint and `xtls-rprx-vision`:

| Format | Use |
| --- | --- |
| `vless://` | Import a standard URI into a compatible GUI client. Includes `security=reality`, `type=tcp`, `encryption=none`, `pbk`, `sid`, `sni`, `fp` and `flow`. |
| QR | Encodes exactly that URI, even when a JSON format is selected. Reopening never creates new credentials. |
| Xray JSON | Standalone core config for Xray 26.10.31; Reality public key uses its current `password` field. Loopback SOCKS inbound on port 10808. |
| sing-box JSON | Standalone core config for sing-box 1.14.4 with uTLS/Reality support. Uses `public_key` and `short_id`. Loopback mixed HTTP/SOCKS inbound on port 10808. |

Select a format to copy or save it. Exports start hidden; QR/reveal are explicit actions. Treat UUIDs, links, QR images and JSON as access credentials. The JSON files do not enable a system VPN, configure TUN/DNS or guarantee leak protection. A GUI app may accept the URI but use a different profile schema for JSON. Windows/macOS/mobile GUI-app import has not been tested. No AmneziaVPN server-manager adoption is promised.

Client exports have an explicit field allowlist. Server private Reality keys, SSH credentials, management state and administrative endpoints are excluded. The Reality public key is required by clients but should still be shared only with intended recipients. The server retains protected device identities, allowing later exports without private-key recovery from an external app.

## Service files and coexistence

- Service: `ashapp-vless.service`; account: `ashapp-vless`.
- Binary: `/usr/local/lib/ashapp/sing-box`.
- State: `/etc/ashapp/vless/state.json`, root-only mode 0600.
- Runtime config: `/etc/ashapp/vless/config.json`, mode 0640, readable by the service group. It contains the server private key and must never be exported or logged.
- Firewall: `/usr/share/netfilter-persistent/plugins.d/91-ashapp-vless`, restoring only its dedicated TCP INPUT accept rule. Provider/network firewalls still need the selected TCP port opened.
- Failed/uncertain updates can retain root-only `recovery-state.json`, `recovery-config.json` and `pending-transaction` in the same protected directory.

AmneziaWG uses its existing kernel interface and UDP port. VLESS uses a separate TCP socket and process. TCP/UDP may share a number; VLESS/SSH/SOCKS5 TCP ports must differ. This architecture and command-isolation tests establish separation; simultaneous traffic through a real kernel AmneziaWG interface and VLESS on a deployed VPS still needs testing.

## Compatibility evidence

Local Windows x64 checks on 2026-11-03 used official, checksum-verified Xray 26.10.31 and sing-box 1.14.4 binaries:

- Both client JSON configurations passed the corresponding core's config checker. The production-generated server config passed sing-box's checker.
- An independent ZXing decoder read the Flutter-generated QR and matched the exported URI byte-for-byte.
- Xray and sing-box clients each passed certificate-verified HTTPS traffic through the same local sing-box Reality/Vision server, using `chrome` and the configured SNI.
- After removing one UUID and applying the server config, its client failed to pass traffic; another device still succeeded.

An initial check against an Xray 26.10.31 **server** reproduced sing-box's [upstream Reality ClientHello incompatibility](https://github.com/SagerNet/sing-box/issues/4520). That is why Ashapp installs the current sing-box server engine instead of downgrading Xray or shipping a known-broken cross-core pairing. This does not promise compatibility with every third-party Xray server, fingerprint preset or future core release. Defaults were tested; other offered fingerprints need their own runtime checks.

The local test uses loopback services and public HTTPS traffic, without SSH or a VPS. Fresh Linux installation, systemd sandboxing, provider firewall behavior, actual AmneziaWG coexistence under traffic, GUI clients and macOS runtime behavior remain unverified. The first Python-based HTTPS probe failed because this Python environment lacked the required certificate chain; the successful data-plane run used Windows Schannel-backed curl with certificate verification enabled. TLS verification was never disabled.

## Repeat the optional core checks

Run regular Flutter and Python tests first. To emit synthetic fixtures from the actual Dart model, set `ASHAPP_VLESS_FIXTURES` to a directory **outside the repository**, then run `flutter test --no-pub test/vless_connection_test.dart` from `flutter/`. No deployed credentials are used.

Obtain official [Xray 26.10.31](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31) and [sing-box 1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) binaries and verify their release digests. From the repository root:

```sh
python tool/validate_vless_exports.py --fixtures /outside/repo/fixtures --xray /path/to/xray --sing-box /path/to/sing-box
```

Add `--decode-qr` after installing `Pillow` and `zxing-cpp` in a separate test environment. Add `--smoke` to bind **loopback-only** ports 24443/10808 and perform public HTTPS checks; both ports must be free. On Windows, optional `--curl C:\Windows\System32\curl.exe` uses the native certificate store. Core binaries and generated fixture files stay outside Git. Smoke checks are optional and do not run during ordinary unit tests.

Official format references: [Xray VLESS](https://xtls.github.io/en/config/outbounds/vless.html), [Xray Reality](https://xtls.github.io/en/config/transports/reality.html), [VLESS URI proposal](https://github.com/XTLS/Xray-core/discussions/716), [sing-box VLESS](https://sing-box.sagernet.org/configuration/outbound/vless/), [sing-box TLS/Reality](https://sing-box.sagernet.org/configuration/shared/tls/). Downloaded cores retain their respective upstream licenses; Ashapp does not bundle them in the desktop app or Git repository.
