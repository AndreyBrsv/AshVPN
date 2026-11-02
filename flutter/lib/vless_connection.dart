import 'dart:convert';
import 'dart:io';

/// One existing device identity, shared by every client export format.
/// Deliberately contains no server private key or administrative credentials.
class VlessConnection {
  VlessConnection.fromJson(Map<String, dynamic> json)
    : name = json['name'] as String,
      uuid = json['uuid'] as String,
      address = json['address'] as String,
      port = json['port'] as int,
      sni = json['sni'] as String,
      publicKey = json['public_key'] as String,
      shortId = json['short_id'] as String,
      fingerprint = json['fingerprint'] as String {
    if (json['flow'] != flow ||
        name.isEmpty ||
        name.length > 256 ||
        name.contains(RegExp(r'[\x00-\x1f\x7f]')) ||
        !RegExp(
          r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        ).hasMatch(uuid) ||
        !validAddress(address) ||
        port < 1 ||
        port > 65535 ||
        !validHostname(sni) ||
        !RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(publicKey) ||
        base64Url.decode('$publicKey=').length != 32 ||
        !RegExp(r'^(?:[0-9a-f]{2}){1,8}$').hasMatch(shortId) ||
        !fingerprints.contains(fingerprint)) {
      throw const FormatException('Invalid VLESS Reality client parameters.');
    }
  }

  static const source = 'vless-reality';
  static const flow = 'xtls-rprx-vision';
  static const fingerprints = ['chrome', 'firefox', 'safari', 'edge'];
  final String name, uuid, address, sni, publicKey, shortId, fingerprint;
  final int port;

  static bool validHostname(String value) => RegExp(
    r'^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$',
  ).hasMatch(value);
  static bool validAddress(String value) =>
      InternetAddress.tryParse(value) != null || validHostname(value);

  String get link => Uri(
    scheme: 'vless',
    userInfo: uuid,
    host: address,
    port: port,
    queryParameters: {
      'encryption': 'none',
      'security': 'reality',
      'type': 'tcp',
      'sni': sni,
      'fp': fingerprint,
      'pbk': publicKey,
      'sid': shortId,
      'flow': flow,
    },
    fragment: name,
  ).toString();

  /// A standalone local SOCKS inbound, not an OS-wide tunnel or GUI profile.
  Map<String, Object> get xray => {
    'log': {'loglevel': 'warning'},
    'inbounds': [
      {
        'tag': 'socks-in',
        'listen': '127.0.0.1',
        'port': 10808,
        'protocol': 'socks',
        'settings': {'auth': 'noauth', 'udp': true},
      },
    ],
    'outbounds': [
      {
        'tag': 'vless-out',
        'protocol': 'vless',
        'settings': {
          'vnext': [
            {
              'address': address,
              'port': port,
              'users': [
                {'id': uuid, 'encryption': 'none', 'flow': flow},
              ],
            },
          ],
        },
        'streamSettings': {
          'network': 'raw',
          'security': 'reality',
          'realitySettings': {
            'serverName': sni,
            'fingerprint': fingerprint,
            'password': publicKey,
            'shortId': shortId,
          },
        },
      },
    ],
  };

  Map<String, Object> get singBox => {
    'log': {'level': 'warn'},
    'inbounds': [
      {
        'type': 'mixed',
        'tag': 'mixed-in',
        'listen': '127.0.0.1',
        'listen_port': 10808,
      },
    ],
    'outbounds': [
      {
        'type': 'vless',
        'tag': 'vless-out',
        'server': address,
        'server_port': port,
        'uuid': uuid,
        'flow': flow,
        'tls': {
          'enabled': true,
          'server_name': sni,
          'utls': {'enabled': true, 'fingerprint': fingerprint},
          'reality': {
            'enabled': true,
            'public_key': publicKey,
            'short_id': shortId,
          },
        },
      },
    ],
  };

  String export(VlessExportFormat format) => switch (format) {
    VlessExportFormat.link => link,
    VlessExportFormat.xray => const JsonEncoder.withIndent('  ').convert(xray),
    VlessExportFormat.singBox => const JsonEncoder.withIndent(
      '  ',
    ).convert(singBox),
  };
}

enum VlessExportFormat {
  link('VLESS link', 'txt'),
  xray('Xray JSON', 'json'),
  singBox('sing-box JSON', 'json');

  const VlessExportFormat(this.label, this.extension);
  final String label, extension;
}

String vpnSourceLabel(String source) => source == VlessConnection.source
    ? 'VLESS + Reality + XTLS Vision'
    : 'AmneziaWG · $source';
