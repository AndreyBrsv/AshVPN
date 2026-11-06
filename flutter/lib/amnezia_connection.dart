import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'client_configuration.dart';

/// Client-only AmneziaVPN guest access, derived from an existing configuration.
/// No administrator credentials or server private keys are accepted here.
class AmneziaConnection {
  AmneziaConnection._(
    this.name,
    this.host,
    this.port,
    this._interface,
    this._peer,
  );

  factory AmneziaConnection.fromConfig(String name, String original) {
    if (name.isEmpty ||
        name.length > 256 ||
        name.contains(RegExp(r'[\x00-\x1f\x7f]'))) {
      throw const FormatException(
        'Enter a client name without control characters.',
      );
    }
    if (!ClientConfiguration(original).withinLimit) {
      throw const FormatException('The client configuration is too large.');
    }
    final interface = <String, String>{}, peer = <String, String>{};
    Map<String, String>? current;
    final seen = <String>{};
    for (var line in const LineSplitter().convert(
      original.replaceFirst(RegExp(r'^\ufeff'), ''),
    )) {
      line = line.split('#').first.trim();
      if (line.isEmpty) continue;
      if (line == '[Interface]' || line == '[Peer]') {
        if (!seen.add(line)) {
          throw const FormatException(
            'Export requires one interface and one peer.',
          );
        }
        current = line == '[Interface]' ? interface : peer;
        continue;
      }
      final separator = line.indexOf('=');
      if (current == null || separator < 1) {
        throw const FormatException('Unsupported client configuration syntax.');
      }
      final field = line.substring(0, separator).trim();
      final value = line.substring(separator + 1).trim();
      final allowed = identical(current, interface)
          ? interfaceFields
          : peerFields;
      if (!allowed.contains(field) ||
          value.isEmpty ||
          value.contains(RegExp(r'[\x00-\x1f\x7f]'))) {
        throw const FormatException(
          'This configuration contains unsupported client fields. Use its original .conf file.',
        );
      }
      if (current.containsKey(field)) {
        throw const FormatException(
          'Duplicate client configuration fields are unsupported.',
        );
      }
      current[field] = value;
    }
    for (final entry in [(interface, 'PrivateKey'), (peer, 'PublicKey')]) {
      if (!_validKey(entry.$1[entry.$2])) {
        throw const FormatException('The saved client key is invalid.');
      }
    }
    for (final entry in [
      (peer, 'PresharedKey'),
      (interface, 'HeaderProtectionKey'),
    ]) {
      if (entry.$1.containsKey(entry.$2) && !_validKey(entry.$1[entry.$2])) {
        throw const FormatException('The saved client key is invalid.');
      }
    }
    if (!_networks(interface['Address']) || !_networks(peer['AllowedIPs'])) {
      throw const FormatException(
        'Client addresses and allowed routes are required.',
      );
    }
    final addresses = interface['Address']!.split(',');
    if (addresses.length != 1 ||
        InternetAddress.tryParse(addresses.single.trim().split('/').first)
                ?.type !=
            InternetAddressType.IPv4) {
      throw const FormatException(
        'AmneziaVPN link export currently needs one IPv4 client address. Use the original .conf file for this client.',
      );
    }
    final endpoint = peer['Endpoint'] ?? '';
    final match = endpoint.startsWith('[')
        ? RegExp(r'^\[([^\]]+)\]:(\d{1,5})$').firstMatch(endpoint)
        : RegExp(r'^([^:\s]+):(\d{1,5})$').firstMatch(endpoint);
    final host = match?[1], port = int.tryParse(match?[2] ?? '');
    if (host == null ||
        !_validHost(host) ||
        port == null ||
        port < 1 ||
        port > 65535) {
      throw const FormatException(
        'The client endpoint needs a valid address and port.',
      );
    }
    final dns = (interface['DNS'] ?? '')
        .split(',')
        .map((part) => part.trim())
        .toList();
    if (dns.isEmpty ||
        dns.length > 2 ||
        dns.any(
          (part) =>
              InternetAddress.tryParse(part)?.type != InternetAddressType.IPv4,
        )) {
      throw const FormatException(
        'AmneziaVPN link export needs one or two IPv4 DNS servers. Use the original .conf file to preserve these DNS settings.',
      );
    }
    for (final entry in [
      (interface, 'MTU', 576, 65535),
      (interface, 'ListenPort', 0, 65535),
      (peer, 'PersistentKeepalive', 0, 65535),
    ]) {
      if (entry.$1[entry.$2] case final String raw) {
        final value = int.tryParse(raw);
        if (value == null || value < entry.$3 || value > entry.$4) {
          throw const FormatException('Invalid numeric client settings.');
        }
      }
    }
    return AmneziaConnection._(
      name,
      host,
      port,
      Map.unmodifiable(interface),
      Map.unmodifiable(peer),
    );
  }

  final String name, host;
  final int port;
  final Map<String, String> _interface, _peer;

  /// Matches AmneziaVPN's version inference from real client parameters.
  /// A container name alone does not determine the protocol generation.
  String? get protocolVersion {
    if (const {
          'HeaderProtectionKey',
          'ContentPaddingAddition',
          'RekeyAfterTime',
          'RekeyTimeout',
          'RejectAfterTime',
          'KeepaliveTimeout',
          'MaxHandshakeAttempts',
        }.any((field) => _interface.containsKey(field)) ||
        const {'RandomTrailers', 'DisableCookies'}.any((field) {
          final value = _interface[field];
          return value != null && value.trim().toLowerCase() != 'off';
        })) {
      return '3.1';
    }
    if (const {'S3', 'S4'}.any(_interface.containsKey) ||
        const {
          'H1',
          'H2',
          'H3',
          'H4',
        }.any((field) => _interface[field]?.contains('-') == true)) {
      return '2';
    }
    if (const {'I1', 'I2', 'I3', 'I4', 'I5'}.any(_interface.containsKey)) {
      return '1.5';
    }
    return null;
  }

  String get container =>
      protocolVersion == null ? 'amnezia-awg' : 'amnezia-awg2';

  static const interfaceFields = {
    'PrivateKey',
    'Address',
    'DNS',
    'MTU',
    'ListenPort',
    'Jc',
    'Jmin',
    'Jmax',
    'S1',
    'S2',
    'S3',
    'S4',
    'H1',
    'H2',
    'H3',
    'H4',
    'I1',
    'I2',
    'I3',
    'I4',
    'I5',
    'HeaderProtectionKey',
    'ContentPaddingAddition',
    'RekeyAfterTime',
    'RekeyTimeout',
    'RejectAfterTime',
    'KeepaliveTimeout',
    'MaxHandshakeAttempts',
    'RandomTrailers',
    'DisableCookies',
  };
  static const peerFields = {
    'PublicKey',
    'PresharedKey',
    'Endpoint',
    'AllowedIPs',
    'PersistentKeepalive',
  };

  static bool _validKey(String? key) {
    try {
      return key != null && key.length == 44 && base64.decode(key).length == 32;
    } on FormatException {
      return false;
    }
  }

  static bool _validHost(String value) =>
      !value.contains('%') &&
      (InternetAddress.tryParse(value) != null ||
          RegExp(
            r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$',
          ).hasMatch(value));

  static bool _networks(String? value) =>
      value != null &&
      value.split(',').every((part) {
        final pieces = part.trim().split('/');
        if (pieces.length != 2) return false;
        final address = InternetAddress.tryParse(pieces[0]);
        final bits = int.tryParse(pieces[1]);
        return address != null &&
            bits != null &&
            bits >= 0 &&
            bits <= (address.type == InternetAddressType.IPv4 ? 32 : 128);
      });

  /// Only allowlisted client parameters are embedded; comments are omitted.
  String get clientConfig =>
      '[Interface]\n${_interface.entries.map((entry) => '${entry.key} = ${entry.value}\n').join()}'
      '\n[Peer]\n${_peer.entries.map((entry) => '${entry.key} = ${entry.value}\n').join()}';

  Map<String, Object> toJson() {
    final dns = (_interface['DNS'] ?? '')
        .split(',')
        .map((part) => part.trim())
        .where((part) => part.isNotEmpty)
        .toList();
    final inner = <String, Object>{
      'config': clientConfig,
      'hostName': host,
      'port': port,
      'client_priv_key': _interface['PrivateKey']!,
      'client_ip': _interface['Address']!,
      'server_pub_key': _peer['PublicKey']!,
      if (_peer['PresharedKey'] case final String psk) 'psk_key': psk,
      'allowed_ips': _peer['AllowedIPs']!
          .split(',')
          .map((part) => part.trim())
          .toList(),
      if (_peer['PersistentKeepalive'] case final String keepalive)
        'persistent_keep_alive': keepalive,
      'mtu': _interface['MTU'] ?? '1376',
      for (final entry in _interface.entries)
        if (!{
          'PrivateKey',
          'Address',
          'DNS',
          'MTU',
          'ListenPort',
        }.contains(entry.key))
          entry.key: entry.value,
    };
    return {
      'format_version': 1,
      'hostName': host,
      'description': name,
      'dns1': dns.first,
      // An absent secondary resolver falls back to Amnezia's global settings.
      // Repeat a single configured resolver rather than adding another one.
      'dns2': dns.length > 1 ? dns[1] : dns.first,
      'defaultContainer': container,
      'containers': [
        {
          'container': container,
          'awg': {
            'isThirdPartyConfig': true,
            if (protocolVersion case final String version)
              'protocol_version': version,
            'port': '$port',
            'transport_proto': 'udp',
            'last_config': jsonEncode(inner),
          },
        },
      ],
    };
  }

  /// Qt qCompress framing: 4-byte big-endian size followed by a zlib stream.
  String get link {
    final json = utf8.encode(jsonEncode(toJson()));
    final size = ByteData(4)..setUint32(0, json.length, Endian.big);
    final bytes = [
      ...size.buffer.asUint8List(),
      ...ZLibEncoder(level: 8).convert(json),
    ];
    return 'vpn://${base64Url.encode(bytes).replaceAll('=', '')}';
  }
}
