import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ashapp/amnezia_connection.dart';
import 'package:ashapp/client_configuration.dart';
import 'package:flutter_test/flutter_test.dart';

// Deliberately synthetic byte sequences, never deployed VPN credentials.
String syntheticKey(int value) => base64Encode(List<int>.filled(32, value));

String configuration({
  String address = '10.8.0.2/32',
  String? dns = '1.1.1.1',
  String endpoint = 'vpn.example.com:585',
  bool presharedKey = true,
  bool keepalive = true,
  bool mtu = true,
  String extraInterface = '',
}) =>
    '''
[Interface]
PrivateKey = ${syntheticKey(11)}
Address = $address
${dns == null ? '' : 'DNS = $dns'}
${mtu ? 'MTU = 1280' : ''}
ListenPort = 12345
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 4294967295
H2 = 2147483648
H3 = 1234567890
H4 = 4000000000
$extraInterface

[Peer]
PublicKey = ${syntheticKey(21)}
${presharedKey ? 'PresharedKey = ${syntheticKey(31)}' : ''}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $endpoint
${keepalive ? 'PersistentKeepalive = 25' : ''}
''';

Map<String, dynamic> protocol(Map<String, dynamic> root) {
  final containers = root['containers'] as List;
  expect(containers, hasLength(1));
  final container = containers.single as Map;
  expect(container['container'], root['defaultContainer']);
  expect(container['container'], isIn(['amnezia-awg', 'amnezia-awg2']));
  return Map<String, dynamic>.from(container['awg'] as Map);
}

Map<String, dynamic> inner(Map<String, dynamic> root) {
  final value = protocol(root)['last_config'];
  expect(value, isA<String>());
  return jsonDecode(value as String) as Map<String, dynamic>;
}

Map<String, dynamic> decodeLink(String link) {
  expect(link, startsWith('vpn://'));
  final encoded = link.substring('vpn://'.length);
  expect(encoded, matches(RegExp(r'^[A-Za-z0-9_-]+$')));
  expect(encoded, isNot(contains('=')));
  final framed = Uint8List.fromList(
    base64Url.decode(base64Url.normalize(encoded)),
  );
  expect(framed.length, greaterThan(6));
  final length = ByteData.sublistView(framed).getUint32(0, Endian.big);
  final zlib = framed.sublist(4);
  // RFC 1950 requires the zlib method/header checksum, unlike raw DEFLATE/gzip.
  expect(zlib.first & 0x0f, 8);
  expect(((zlib[0] << 8) | zlib[1]) % 31, 0);
  final jsonBytes = ZLibDecoder().convert(zlib);
  expect(length, jsonBytes.length);
  return jsonDecode(utf8.decode(jsonBytes)) as Map<String, dynamic>;
}

void expectSafeRejection(String input, {String name = 'Phone'}) {
  try {
    AmneziaConnection.fromConfig(name, input);
    fail('Unsupported configuration was accepted.');
  } on FormatException catch (error) {
    expect(error.source, isNull);
    expect(error.message, isNot(contains(syntheticKey(11))));
    expect(error.message, isNot(contains(syntheticKey(21))));
    expect(error.message, isNot(contains(syntheticKey(31))));
    expect(error.message, isNot(contains('admin-secret-placeholder')));
    expect(error.message, isNot(contains('server-secret-placeholder')));
  }
}

void main() {
  group('AmneziaVPN native guest schema', () {
    test('modern generations use the matching AWG2 container and version', () {
      for (final entry in {
        'S3 = 0\nS4 = 0': '2',
        'I1 = <b 0x01020304>': '1.5',
        'ContentPaddingAddition = 10-100': '3.1',
        'RandomTrailers = on': '3.1',
      }.entries) {
        final connection = AmneziaConnection.fromConfig(
          'Existing device',
          configuration(extraInterface: entry.key),
        );
        final root = decodeLink(connection.link);
        expect(root['defaultContainer'], 'amnezia-awg2');
        expect(protocol(root)['protocol_version'], entry.value);
        expect(inner(root)['client_priv_key'], syntheticKey(11));
        expect(inner(root)['server_pub_key'], syntheticKey(21));
        expect(inner(root)['psk_key'], syntheticKey(31));
        expect(inner(root)['config'], connection.clientConfig);
      }
    });

    test('header ranges imply AWG2 without inventing padding settings', () {
      final original = configuration().replaceFirst(
        'H1 = 4294967295',
        'H1 = 100-200',
      );
      final connection = AmneziaConnection.fromConfig(
        'Existing device',
        original,
      );
      final root = decodeLink(connection.link);
      expect(protocol(root)['protocol_version'], '2');
      expect(inner(root)['H1'], '100-200');
      expect(inner(root).containsKey('S3'), isFalse);
      expect(inner(root).containsKey('S4'), isFalse);
      expect(
        connection.clientConfig,
        contains('PrivateKey = ${syntheticKey(11)}'),
      );
    });

    test(
      'disabled modern toggles do not relabel an existing legacy profile',
      () {
        final connection = AmneziaConnection.fromConfig(
          'Legacy device',
          configuration(
            extraInterface: 'RandomTrailers = off\nDisableCookies = OFF',
          ),
        );
        expect(connection.container, 'amnezia-awg');
        expect(
          protocol(connection.toJson()).containsKey('protocol_version'),
          isFalse,
        );
      },
    );

    test('preserves the existing client identity and only client settings', () {
      final connection = AmneziaConnection.fromConfig('Phone', configuration());
      final root = connection.toJson();
      expect(
        root.keys,
        unorderedEquals([
          'format_version',
          'hostName',
          'description',
          'dns1',
          'dns2',
          'defaultContainer',
          'containers',
        ]),
      );
      expect(root['format_version'], 1);
      expect(root['hostName'], 'vpn.example.com');
      expect(root['description'], 'Phone');
      expect(root['defaultContainer'], 'amnezia-awg');
      final awg = protocol(root);
      expect(awg, {
        'isThirdPartyConfig': true,
        'port': '585',
        'transport_proto': 'udp',
        'last_config': isA<String>(),
      });
      expect(inner(root), {
        'config': connection.clientConfig,
        'hostName': 'vpn.example.com',
        'port': 585,
        'client_priv_key': syntheticKey(11),
        'client_ip': '10.8.0.2/32',
        'server_pub_key': syntheticKey(21),
        'psk_key': syntheticKey(31),
        'allowed_ips': ['0.0.0.0/0', '::/0'],
        'persistent_keep_alive': '25',
        'mtu': '1280',
        'Jc': '4',
        'Jmin': '40',
        'Jmax': '70',
        'S1': '0',
        'S2': '0',
        'H1': '4294967295',
        'H2': '2147483648',
        'H3': '1234567890',
        'H4': '4000000000',
      });
      final serialized = jsonEncode(root);
      for (final field in [
        'userName',
        'password',
        'server_priv_key',
        'private_key',
        'config_version',
        'ssh_port',
      ]) {
        expect(serialized, isNot(contains('"$field"')));
      }
      expect(connection.link, connection.link);
      expect(connection.clientConfig, contains('ListenPort = 12345'));
    });

    test('single DNS stays explicit in both native resolver positions', () {
      final root = AmneziaConnection.fromConfig(
        'Phone',
        configuration(),
      ).toJson();
      expect(root['dns1'], '1.1.1.1');
      expect(root['dns2'], '1.1.1.1');
    });

    test('two DNS servers retain their order', () {
      final root = AmneziaConnection.fromConfig(
        'Phone',
        configuration(dns: '9.9.9.9, 149.112.112.112'),
      ).toJson();
      expect(root['dns1'], '9.9.9.9');
      expect(root['dns2'], '149.112.112.112');
    });

    test('optional keys stay absent and MTU has the native default', () {
      final value = inner(
        AmneziaConnection.fromConfig(
          'Phone',
          configuration(presharedKey: false, keepalive: false, mtu: false),
        ).toJson(),
      );
      expect(value.containsKey('psk_key'), isFalse);
      expect(value.containsKey('persistent_keep_alive'), isFalse);
      expect(value['mtu'], '1376');
      expect(value['client_priv_key'], syntheticKey(11));
    });

    test(
      'all supported extension values retain their string representations',
      () {
        final fields = <String, String>{
          'S3': '12',
          'S4': '16',
          'I1': '<b 0x01020304>',
          'I2': '<r 10>',
          'I3': '<c>',
          'I4': '<b 0xff>',
          'I5': '<r 4>',
          'HeaderProtectionKey': syntheticKey(41),
          'ContentPaddingAddition': '12',
          'RekeyAfterTime': '120',
          'RekeyTimeout': '5',
          'RejectAfterTime': '180',
          'KeepaliveTimeout': '10',
          'MaxHandshakeAttempts': '90',
          'RandomTrailers': 'true',
          'DisableCookies': 'false',
        };
        final connection = AmneziaConnection.fromConfig(
          'Phone',
          configuration(
            extraInterface: fields.entries
                .map((e) => '${e.key} = ${e.value}')
                .join('\n'),
          ),
        );
        final value = inner(connection.toJson());
        for (final entry in fields.entries) {
          expect(value[entry.key], entry.value, reason: entry.key);
          expect(value[entry.key], isA<String>(), reason: entry.key);
          expect(
            connection.clientConfig,
            contains('${entry.key} = ${entry.value}'),
          );
        }
      },
    );

    test('IPv4, DNS and bracketed IPv6 endpoints retain host and port', () {
      for (final endpoint in {
        '203.0.113.10:585': '203.0.113.10',
        'vpn.example.com:443': 'vpn.example.com',
        '[2001:db8::1]:65535': '2001:db8::1',
      }.entries) {
        final connection = AmneziaConnection.fromConfig(
          'Phone',
          configuration(endpoint: endpoint.key),
        );
        final expectedPort = int.parse(endpoint.key.split(':').last);
        expect(connection.host, endpoint.value);
        expect(connection.port, expectedPort);
        expect(inner(connection.toJson())['hostName'], endpoint.value);
        expect(inner(connection.toJson())['port'], expectedPort);
        expect(protocol(connection.toJson())['port'], '$expectedPort');
      }
    });

    test(
      'CRLF, BOM and comments never add administrative data to the link',
      () {
        final original =
            '\ufeff# password = admin-secret-placeholder\r\n'
            '# server_priv_key = server-secret-placeholder\r\n'
            '${configuration().replaceAll('\n', '\r\n')}';
        final connection = AmneziaConnection.fromConfig('Phone', original);
        final root = decodeLink(connection.link);
        final serialized = jsonEncode(root);
        expect(serialized, isNot(contains('admin-secret-placeholder')));
        expect(serialized, isNot(contains('server-secret-placeholder')));
        expect(connection.clientConfig, isNot(contains('\r')));
        expect(connection.clientConfig, isNot(contains('#')));
        expect(inner(root)['client_priv_key'], syntheticKey(11));
        expect(inner(root)['config'], connection.clientConfig);
      },
    );
  });

  group('Qt qCompress link framing', () {
    test('decodes through independent base64url, frame and zlib steps', () {
      final connection = AmneziaConnection.fromConfig('Phone', configuration());
      final root = decodeLink(connection.link);
      expect(root['format_version'], 1);
      expect(root['description'], 'Phone');
      expect(protocol(root)['isThirdPartyConfig'], isTrue);
      expect(inner(root)['client_priv_key'], syntheticKey(11));
      expect(inner(root)['server_pub_key'], syntheticKey(21));
      expect(inner(root)['psk_key'], syntheticKey(31));
    });

    test('length prefix counts UTF8 bytes rather than Unicode code units', () {
      const name = 'Телефон / café 📱';
      final connection = AmneziaConnection.fromConfig(name, configuration());
      final encoded = connection.link.substring('vpn://'.length);
      final framed = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(encoded)),
      );
      final payload = ZLibDecoder().convert(framed.sublist(4));
      final text = utf8.decode(payload);
      expect(
        ByteData.sublistView(framed).getUint32(0, Endian.big),
        payload.length,
      );
      expect(payload.length, greaterThan(text.length));
      expect((jsonDecode(text) as Map)['description'], name);
      expect(decodeLink(connection.link)['description'], name);
    });
  });

  group(
    'unsupported native settings fail safely for original-conf fallback',
    () {
      test('requires one IPv4 client address without changing routes', () {
        for (final address in [
          '2001:db8::2/128',
          '10.8.0.2/32, 2001:db8::2/128',
          '10.8.0.2/32, 10.8.0.3/32',
          '10.8.0.2/33',
          '10.8.0.2',
          '10.8.0.2/-1',
        ]) {
          expectSafeRejection(configuration(address: address));
        }
      });

      test('rejects unsupported DNS instead of changing resolver policy', () {
        for (final dns in <String?>[
          null,
          '',
          '2606:4700:4700::1111',
          '1.1.1.1, 2606:4700:4700::1111',
          '1.1.1.1, 1.0.0.1, 9.9.9.9',
          'vpn.example.com',
          '1.1.1.1, search.example.com',
          '1.1.1.1,',
        ]) {
          expectSafeRejection(configuration(dns: dns));
        }
      });

      test('requires one peer and rejects duplicate fields and sections', () {
        final base = configuration();
        for (final invalid in [
          '$base\n[Peer]\nPublicKey = ${syntheticKey(21)}\n',
          '$base\n[Interface]\nPrivateKey = ${syntheticKey(11)}\n',
          base.replaceFirst('Jc = 4', 'Jc = 4\nJc = 5'),
          base.replaceFirst(
            'Endpoint =',
            'PublicKey = ${syntheticKey(21)}\nEndpoint =',
          ),
          base.replaceFirst('[Peer]', '[Other]'),
          base.replaceFirst('[Peer]', ''),
        ]) {
          expectSafeRejection(invalid);
        }
      });

      test(
        'rejects shell hooks and administrative fields without echoing them',
        () {
          for (final field in [
            'PreUp = echo admin-secret-placeholder',
            'PostUp = echo server-secret-placeholder',
            'PostDown = false',
            'SaveConfig = true',
            'Table = off',
            'server_priv_key = server-secret-placeholder',
            'password = admin-secret-placeholder',
            'userName = root',
          ]) {
            expectSafeRejection(configuration(extraInterface: field));
          }
        },
      );

      test(
        'invalid keys, endpoint and numeric fields cannot produce a link',
        () {
          final base = configuration();
          for (final invalid in [
            base.replaceFirst(syntheticKey(11), 'invalid-private-placeholder'),
            base.replaceFirst(syntheticKey(21), 'invalid-public-placeholder'),
            base.replaceFirst(syntheticKey(31), 'invalid-psk-placeholder'),
            configuration(
              extraInterface: 'HeaderProtectionKey = invalid-placeholder',
            ),
            configuration(endpoint: 'vpn.example.com:0'),
            configuration(endpoint: 'vpn.example.com:65536'),
            configuration(endpoint: 'https://vpn.example.com:585'),
            configuration(endpoint: 'vpn.example.com'),
            configuration(endpoint: '[fe80::1%en0]:585'),
            base.replaceFirst('MTU = 1280', 'MTU = 575'),
            base.replaceFirst('ListenPort = 12345', 'ListenPort = 65536'),
            base.replaceFirst(
              'PersistentKeepalive = 25',
              'PersistentKeepalive = -1',
            ),
            base.replaceFirst(
              'AllowedIPs = 0.0.0.0/0, ::/0',
              'AllowedIPs = invalid',
            ),
          ]) {
            expectSafeRejection(invalid);
          }
        },
      );

      test(
        'bounds input and rejects controls without exposing access material',
        () {
          for (final name in ['', 'x' * 257, 'Phone\nroot', 'Phone\x00']) {
            expectSafeRejection(configuration(), name: name);
          }
          expectSafeRejection('${configuration()}\x00');
          expectSafeRejection(
            configuration(extraInterface: 'I1 = bad\x1bvalue'),
          );
          expectSafeRejection(
            '${configuration()}\n# ${'x' * ClientConfiguration.maxBytes}',
          );
        },
      );
    },
  );
}
