import 'dart:convert';
import 'dart:io';

import 'package:ashapp/amnezia_connection.dart';
import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/private_qr.dart';
import 'package:ashapp/ui_components.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

String _key(int byte) => base64.encode(List.filled(32, byte));

String _config({bool dns = true, int client = 12}) =>
    '[Interface]\r\nPrivateKey = ${_key(client)}\r\n'
    'Address = 10.8.0.$client/32\r\n'
    '${dns ? 'DNS = 1.1.1.1\r\n' : ''}'
    'Jc = 4\r\nJmin = 40\r\nJmax = 70\r\n'
    'S1 = 0\r\nS2 = 0\r\nH1 = 1234567890\r\n'
    'H2 = 2345678901\r\nH3 = 3456789012\r\nH4 = 456789012\r\n'
    '\r\n[Peer]\r\nPublicKey = ${_key(3)}\r\n'
    'PresharedKey = ${_key(4)}\r\nAllowedIPs = 0.0.0.0/0\r\n'
    'Endpoint = 203.0.113.10:585\r\nPersistentKeepalive = 25\r\n';

void _desktop(WidgetTester tester) {
  tester.view.physicalSize = const Size(1200, 1400);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
}

Future<void> _dialog(
  WidgetTester tester,
  String config, {
  String name = 'Existing phone',
  String endpoint = '203.0.113.10:22',
  bool initialQr = false,
}) => tester.pumpWidget(
  AshappApp(
    home: Scaffold(
      body: ClientExportDialog(
        name: name,
        config: config,
        endpoint: endpoint,
        initialQr: initialQr,
      ),
    ),
  ),
);

Future<void> _native(WidgetTester tester) async {
  await tester.tap(find.byType(DropdownButtonFormField<bool>));
  await tester.pumpAndSettle();
  await tester.tap(find.text('Native configuration (.conf)').last);
  await tester.pumpAndSettle();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  String? clipboard;
  final picks = <MethodCall>[];
  final saves = <MethodCall>[];
  const picker = MethodChannel('plugins.flutter.io/file_selector');
  const privateExport = MethodChannel('ashapp/private-export');

  setUp(() {
    clipboard = null;
    picks.clear();
    saves.clear();
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        clipboard = (call.arguments as Map)['text'] as String;
      }
      return null;
    });
    messenger.setMockMethodCallHandler(picker, (call) async {
      picks.add(call);
      return '/synthetic/selected-private-export';
    });
    messenger.setMockMethodCallHandler(privateExport, (call) async {
      saves.add(call);
      return null;
    });
  });

  tearDown(() {
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    for (final channel in [SystemChannels.platform, picker, privateExport]) {
      messenger.setMockMethodCallHandler(channel, null);
    }
  });

  testWidgets('default export copies the existing client as an Amnezia link', (
    tester,
  ) async {
    _desktop(tester);
    final original = _config();
    final link = AmneziaConnection.fromConfig('Existing phone', original).link;
    await _dialog(tester, original);
    await tester.pumpAndSettle();

    expect(find.byTooltip('Copy Amnezia link'), findsOneWidget);
    expect(find.text('Save .vpn'), findsOneWidget);
    expect(find.text('Show QR code'), findsNothing);
    expect(find.byType(PrivateQr), findsNothing);
    for (final secret in [_key(12), _key(4), link]) {
      expect(find.textContaining(secret), findsNothing);
    }

    await tester.tap(find.byTooltip('Copy Amnezia link'));
    await tester.pumpAndSettle();
    expect(clipboard, link);
    expect(clipboard, startsWith('vpn://'));
    expect(find.textContaining(link), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('native selection preserves exact CRLF content for copy and QR', (
    tester,
  ) async {
    _desktop(tester);
    final original = _config();
    await _dialog(tester, original);
    await _native(tester);
    expect(find.byTooltip('Copy Amnezia link'), findsNothing);
    expect(find.text('Save .conf'), findsOneWidget);
    await tester.tap(find.byTooltip('Copy configuration'));
    await tester.pumpAndSettle();
    expect(clipboard, original);

    await tester.tap(find.text('Show QR code'));
    await tester.pumpAndSettle();
    expect(tester.widget<PrivateQr>(find.byType(PrivateQr)).data, original);
    expect(find.textContaining(_key(12)), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('opening an existing QR starts in native configuration format', (
    tester,
  ) async {
    _desktop(tester);
    final original = _config();
    await _dialog(tester, original, initialQr: true);
    await tester.pumpAndSettle();
    expect(find.byTooltip('Copy configuration'), findsOneWidget);
    expect(find.text('Save .conf'), findsOneWidget);
    expect(tester.widget<PrivateQr>(find.byType(PrivateQr)).data, original);
    await tester.tap(find.byTooltip('Copy configuration'));
    await tester.pumpAndSettle();
    expect(clipboard, original);
  });

  testWidgets('unsupported DNS preserves original file and explains fallback', (
    tester,
  ) async {
    _desktop(tester);
    final original = _config(dns: false);
    await _dialog(tester, original);
    await tester.pumpAndSettle();
    expect(find.textContaining('one or two IPv4 DNS servers'), findsOneWidget);
    expect(find.byTooltip('Copy Amnezia link'), findsNothing);
    expect(find.text('Save .conf'), findsOneWidget);
    await tester.tap(find.byTooltip('Copy configuration'));
    await tester.pumpAndSettle();
    expect(clipboard, original);
    expect(find.textContaining(_key(12)), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'format selection saves selected bytes through protected export',
    (tester) async {
      _desktop(tester);
      final original = _config();
      final link = AmneziaConnection.fromConfig(
        'Existing phone',
        original,
      ).link;
      await _dialog(tester, original);
      await tester.tap(find.text('Save .vpn'));
      await tester.pumpAndSettle();
      expect(picks.single.method, 'getSavePath');
      expect(
        (picks.single.arguments as Map)['suggestedName'],
        'Existing_phone-203_0_113_10_22.vpn',
      );
      expect(saves.single.method, 'save');
      expect(
        (saves.single.arguments as Map)['path'],
        '/synthetic/selected-private-export',
      );
      expect((saves.single.arguments as Map)['bytes'], utf8.encode(link));

      await _native(tester);
      await tester.tap(find.text('Save .conf'));
      await tester.pumpAndSettle();
      expect((picks.last.arguments as Map)['suggestedName'], endsWith('.conf'));
      expect(saves, hasLength(2));
      expect((saves.last.arguments as Map)['bytes'], utf8.encode(original));
      expect(tester.takeException(), isNull);
    },
    skip: !Platform.isWindows && !Platform.isMacOS,
  );

  testWidgets('client-row copy reads only the selected original peer', (
    tester,
  ) async {
    _desktop(tester);
    final h = Harness();
    addTearDown(h.vm.dispose);
    final original = _config();
    h.server.configuration = original;
    h.server.clientRows = [
      {
        'name': 'Phone',
        'source': 'amnezia-awg2',
        'public_key': _key(12),
        'can_export': true,
      },
    ];
    await h.vm.connect(
      const ConnectionDetails(
        host: '203.0.113.10',
        port: 22,
        user: 'root',
        password: 'test-session-placeholder',
      ),
      (_, _) async => true,
    );
    await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Clients'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byTooltip('Copy Amnezia link'));
    await tester.tap(find.byTooltip('Copy Amnezia link'));
    await tester.pumpAndSettle();

    expect(clipboard, AmneziaConnection.fromConfig('Phone', original).link);
    expect(h.server.calls.where((call) => call.$1 == 'get-client').single.$2, [
      'Phone',
      'amnezia-awg2',
      _key(12),
    ]);
    expect(
      h.server.calls.any(
        (call) => {'add-client', 'import-client'}.contains(call.$1),
      ),
      isFalse,
    );
    expect(find.byType(ClientExportDialog), findsNothing);
    expect(find.textContaining(_key(12)), findsNothing);
    expect(find.textContaining(clipboard!), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'reused dialog replaces access when its endpoint and client change',
    (tester) async {
      _desktop(tester);
      await _dialog(tester, _config());
      await _native(tester);
      await tester.tap(find.text('Show QR code'));
      await tester.pumpAndSettle();
      final second = _config(client: 13);
      await _dialog(
        tester,
        second,
        name: 'Second phone',
        endpoint: '203.0.113.10:2222',
      );
      await tester.pumpAndSettle();
      expect(find.byType(PrivateQr), findsNothing);
      expect(find.byTooltip('Copy Amnezia link'), findsOneWidget);
      await tester.tap(find.byTooltip('Copy Amnezia link'));
      await tester.pumpAndSettle();
      expect(
        clipboard,
        AmneziaConnection.fromConfig('Second phone', second).link,
      );
      expect(find.textContaining(_key(12)), findsNothing);
      expect(find.textContaining(_key(13)), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );
}
