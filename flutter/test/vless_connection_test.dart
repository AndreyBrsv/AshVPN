import 'dart:convert';
import 'dart:io';

import 'package:ashapp/connection_details.dart';
import 'package:ashapp/create_client_dialog.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/server_workspace.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:ashapp/setup_wizard.dart';
import 'package:ashapp/vless_connection.dart';
import 'package:ashapp/vless_export_dialog.dart';
import 'package:ashapp/private_qr.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'support/fakes.dart';

Map<String, dynamic> fixture({String address = '203.0.113.10'}) => {
  'name': 'Phone / café & tablet',
  'uuid': '00000000-0000-4000-8000-000000000001',
  'address': address,
  'port': 443,
  'sni': 'www.microsoft.com',
  // Public test vector from RFC 7748 section 6.1, never a deployed credential.
  'public_key': 'hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo',
  'short_id': '0123456789abcdef',
  'fingerprint': 'chrome',
  'flow': VlessConnection.flow,
};

const login = ConnectionDetails(
  host: '203.0.113.10',
  port: 22,
  user: 'root',
  password: 'test-session-placeholder',
);

ServerTemplate answers({bool awg = true}) => ServerTemplate(
  name: 'Both',
  awgDeployment: 'host',
  blockPing: false,
  disableRoot: false,
  installAwg: awg,
  installSocks: false,
  awgPort: 585,
  clientNames: awg ? ['phone'] : [],
  createAdmin: false,
  installVless: true,
  vlessPort: 8443,
  realitySni: 'www.microsoft.com',
  vlessClientNames: ['phone'],
);

void main() {
  test(
    'link escapes labels, brackets IPv6 and preserves all connection fields',
    () {
      for (final host in ['203.0.113.10', 'vpn.example.com', '2001:db8::1']) {
        final c = VlessConnection.fromJson(fixture(address: host));
        final uri = Uri.parse(c.link);
        expect(uri.scheme, 'vless');
        expect(uri.userInfo, c.uuid);
        expect(uri.host.replaceAll('[', '').replaceAll(']', ''), host);
        expect(uri.port, 443);
        expect(Uri.decodeComponent(uri.fragment), c.name);
        expect(uri.queryParameters, {
          'encryption': 'none',
          'security': 'reality',
          'type': 'tcp',
          'sni': c.sni,
          'fp': c.fingerprint,
          'pbk': c.publicKey,
          'sid': c.shortId,
          'flow': VlessConnection.flow,
        });
      }
    },
  );

  test('all exports share identity and never echo unknown server fields', () {
    final input = fixture()
      ..addAll({
        'private_key': 'server-private-placeholder',
        'admin_password': 'admin-placeholder',
      });
    final c = VlessConnection.fromJson(input);
    final x = jsonDecode(c.export(VlessExportFormat.xray)) as Map;
    final outbound = x['outbounds'][0];
    final user = outbound['settings']['vnext'][0]['users'][0];
    expect(user, {
      'id': c.uuid,
      'encryption': 'none',
      'flow': VlessConnection.flow,
    });
    expect(outbound['settings']['vnext'][0]['address'], c.address);
    expect(outbound['settings']['vnext'][0]['port'], c.port);
    expect(outbound['streamSettings']['realitySettings'], {
      'serverName': c.sni,
      'fingerprint': c.fingerprint,
      'password': c.publicKey,
      'shortId': c.shortId,
    });
    final s = jsonDecode(c.export(VlessExportFormat.singBox)) as Map;
    final so = s['outbounds'][0];
    expect(so['uuid'], c.uuid);
    expect(so['flow'], VlessConnection.flow);
    expect(so['server'], c.address);
    expect(so['server_port'], c.port);
    expect(so['tls']['server_name'], c.sni);
    expect(so['tls']['utls'], {'enabled': true, 'fingerprint': c.fingerprint});
    expect(so['tls']['reality'], {
      'enabled': true,
      'public_key': c.publicKey,
      'short_id': c.shortId,
    });
    for (final format in VlessExportFormat.values) {
      expect(c.export(format), isNot(contains('server-private-placeholder')));
      expect(c.export(format), isNot(contains('admin-placeholder')));
      expect(c.export(format), isNot(contains('privateKey')));
    }
    expect(x['inbounds'][0]['listen'], '127.0.0.1');
    expect(s['inbounds'][0]['listen'], '127.0.0.1');
  });

  test('invalid Reality inputs cannot produce a partially valid export', () {
    for (final entry in <String, dynamic>{
      'port': 0,
      'address': 'bad/host',
      'uuid': 'not-a-uuid',
      'sni': 'https://wrong',
      'public_key': 'bad',
      'short_id': '123',
      'fingerprint': 'unsafe',
      'flow': 'wrong',
    }.entries) {
      expect(
        () => VlessConnection.fromJson({...fixture(), entry.key: entry.value}),
        throwsFormatException,
        reason: entry.key,
      );
    }
  });

  test(
    'templates round-trip both protocols and migrate old templates safely',
    () {
      final a = answers();
      final b = ServerTemplate.fromJson(jsonDecode(jsonEncode(a.toJson())));
      expect(b.installAwg, isTrue);
      expect(b.installVless, isTrue);
      expect(b.vlessClientNames, ['phone']);
      expect(b.vlessPort, 8443);
      final old = a.toJson()
        ..removeWhere(
          (k, _) => {
            'install_vless',
            'vless_port',
            'reality_sni',
            'reality_fingerprint',
            'vless_client_names',
          }.contains(k),
        );
      expect(ServerTemplate.fromJson(old).installVless, isFalse);
      expect(ServerTemplate.fromJson(old).vlessClientNames, isEmpty);
    },
  );

  test(
    'TCP port collisions are rejected while TCP/UDP same number is allowed',
    () {
      expect(const SetupSecrets().validate(answers()), isNull);
      final fields = answers().toJson()..['vless_port'] = 22;
      expect(
        const SetupSecrets().validate(ServerTemplate.fromJson(fields)),
        contains('different TCP ports'),
      );
      fields['vless_port'] = 585;
      expect(
        const SetupSecrets().validate(ServerTemplate.fromJson(fields)),
        isNull,
      );
    },
  );

  test(
    'both protocols provision through one plan with scoped same-name clients',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login, (_, _) async => true);
      expect(await h.vm.provision(answers(), const SetupSecrets()), isTrue);
      expect(h.server.state['awg'], isTrue);
      expect(h.server.state['vless'], isTrue);
      expect(h.vm.clientSources, containsAll(['awg0', VlessConnection.source]));
      final creates = h.server.calls
          .where((c) => c.$1 == 'add-client')
          .map((c) => c.$2)
          .toList();
      expect(creates, [
        ['phone'],
        ['phone', VlessConnection.source],
      ]);
      expect(h.server.calls.singleWhere((c) => c.$1 == 'install-vless').$2, [
        login.host,
        '8443',
        'www.microsoft.com',
        'chrome',
      ]);
    },
  );

  test('VLESS-only setup does not install or control AmneziaWG', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(login, (_, _) async => true);
    expect(
      await h.vm.provision(answers(awg: false), const SetupSecrets()),
      isTrue,
    );
    expect(h.server.calls.any((c) => c.$1.contains('awg')), isFalse);
  });

  test(
    'an export with a different UUID is rejected without revealing that client',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.vlessConnection = {
        ...fixture(),
        'uuid': '00000000-0000-4000-8000-000000000002',
      };
      await h.vm.connect(login, (_, _) async => true);
      expect(
        await h.vm.vlessConnection('Phone', fixture()['uuid'] as String),
        isNull,
      );
      expect(h.vm.error, contains('identity changed'));
    },
  );

  test('repeated dual-protocol setup preserves services and does not duplicate same-name devices', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.server.state.addAll({
      'awg': true,
      'awg_configured': true,
      'interface': 'awg0',
      'kernel': true,
      'vless': true,
      'vless_configured': true,
      'vless_port': 443,
    });
    h.server.clientRows = [
      {
        'name': 'phone',
        'source': 'awg0',
        'public_key': 'synthetic-public-placeholder',
      },
      {
        'name': 'phone',
        'source': VlessConnection.source,
        'public_key': fixture()['uuid'],
      },
    ];
    await h.vm.connect(login, (_, _) async => true);
    expect(await h.vm.provision(answers(), const SetupSecrets()), isTrue);
    expect(
      h.server.calls.any(
        (c) => c.$1 == 'add-client' || c.$1 == 'install-awg-configured',
      ),
      isFalse,
    );
    expect(h.vm.server['vless_port'], 443);
  });

  test(
    'VLESS exports and revocations remain bound to server, SSH port and UUID',
    () async {
      final h = Harness();
      final workspace = ServerWorkspace(h.vm);
      addTearDown(workspace.dispose);
      h.server.state.addAll({'vless_configured': true, 'vless': true});
      h.server.vlessConnection = fixture();
      await h.vm.connect(login, (_, _) async => true);
      final other = workspace.create();
      await other.connect(
        const ConnectionDetails(
          host: '203.0.113.10',
          port: 2222,
          user: 'root',
          password: 'other-test-placeholder',
        ),
        (_, _) async => true,
      );
      workspace.select(other);
      final c = await h.vm.vlessConnection(
        'Same name',
        fixture()['uuid'] as String,
      );
      expect(c!.uuid, fixture()['uuid']);
      expect(
        await h.vm.revokeClient(
          'Same name',
          source: VlessConnection.source,
          publicKey: c.uuid,
        ),
        isTrue,
      );
      expect(h.server.calls.where((c) => c.$1 == 'revoke-client').single.$2, [
        'Same name',
        VlessConnection.source,
        c.uuid,
      ]);
      expect(
        h.servers['203.0.113.10:2222']!.calls.any(
          (c) => c.$1.endsWith('-client'),
        ),
        isFalse,
      );
    },
  );

  testWidgets(
    'format selection copies matching JSON and QR always contains exact link',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 1400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      String? clipboard;
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        (call) async {
          if (call.method == 'Clipboard.setData') {
            clipboard = (call.arguments as Map)['text'] as String;
          }
          return null;
        },
      );
      addTearDown(
        () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
          SystemChannels.platform,
          null,
        ),
      );
      final c = VlessConnection.fromJson(fixture());
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: VlessExportDialog(
              connection: c,
              endpoint: '203.0.113.10:22',
              initialQr: true,
            ),
          ),
        ),
      );
      expect(tester.widget<PrivateQr>(find.byType(PrivateQr)).data, c.link);
      await tester.tap(find.byTooltip('Copy connection'));
      await tester.pump();
      expect(clipboard, c.link);
      for (final format in [
        VlessExportFormat.xray,
        VlessExportFormat.singBox,
      ]) {
        await tester.tap(
          find.byType(DropdownButtonFormField<VlessExportFormat>),
        );
        await tester.pumpAndSettle();
        await tester.tap(find.text(format.label).last);
        await tester.pumpAndSettle();
        await tester.tap(find.byTooltip('Copy connection'));
        await tester.pump();
        expect(clipboard, c.export(format));
        expect(tester.widget<PrivateQr>(find.byType(PrivateQr)).data, c.link);
        expect(find.text(c.export(format)), findsNothing);
      }
    },
  );

  testWidgets(
    'create-client protocol selector offers VLESS alongside AmneziaWG',
    (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: CreateClientDialog(
              sources: const ['awg0', VlessConnection.source],
              endpoint: '203.0.113.10:22',
            ),
          ),
        ),
      );
      await tester.tap(find.byType(DropdownButtonFormField<String>));
      await tester.pumpAndSettle();
      await tester.tap(find.text(vpnSourceLabel(VlessConnection.source)).last);
      await tester.pumpAndSettle();
      expect(find.textContaining('separate UUID'), findsOneWidget);
      expect(find.text('Client DNS address'), findsNothing);
    },
  );

  testWidgets(
    'wizard templates prefill VLESS settings independently from AmneziaWG',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 1400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final h = Harness();
      addTearDown(h.vm.dispose);
      await tester.pumpWidget(
        MaterialApp(
          home: SetupWizard(
            controller: h.vm,
            editTemplate: true,
            initial: answers(awg: false),
          ),
        ),
      );
      for (var i = 0; i < 3; i++) {
        await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
        await tester.pumpAndSettle();
      }
      expect(find.text('Install VLESS + Reality'), findsOneWidget);
      expect(
        find.widgetWithText(TextFormField, 'VLESS TCP port'),
        findsOneWidget,
      );
      expect(find.text('8443'), findsOneWidget);
    },
  );

  test(
    'optional core validation fixtures use exactly the production exporters',
    () {
      final folder = Platform.environment['ASHAPP_VLESS_FIXTURES'];
      if (folder == null) return;
      final c = VlessConnection.fromJson({
        ...fixture(address: '127.0.0.1'),
        'port': 24443,
      });
      Directory(folder).createSync(recursive: true);
      File('$folder/xray-client.json')
          .writeAsStringSync(c.export(VlessExportFormat.xray));
      File('$folder/sing-box-client.json')
          .writeAsStringSync(c.export(VlessExportFormat.singBox));
      File('$folder/link.txt').writeAsStringSync(c.link);
      final second = VlessConnection.fromJson({
        ...fixture(address: '127.0.0.1'),
        'port': 24443,
        'uuid': '00000000-0000-4000-8000-000000000002',
        'short_id': '1123456789abcdef',
      });
      File('$folder/xray-second-client.json')
          .writeAsStringSync(second.export(VlessExportFormat.xray));
    },
  );
  testWidgets(
    'optional QR fixture renders the exact exported link for independent decoding',
    (tester) async {
      final folder = Platform.environment['ASHAPP_VLESS_FIXTURES'];
      if (folder == null) return;
      final c = VlessConnection.fromJson({
        ...fixture(address: '127.0.0.1'),
        'port': 24443,
      });
      await tester.runAsync(() async {
        final bytes = await QrPainter(
          data: c.link,
          version: QrVersions.auto,
          errorCorrectionLevel: QrErrorCorrectLevel.L,
        ).toImageData(1000);
        File('$folder/link-qr.png')
            .writeAsBytesSync(bytes!.buffer.asUint8List());
      });
    },
  );
}
