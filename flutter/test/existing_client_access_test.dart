import 'dart:convert';

import 'package:ashapp/client_configuration.dart';
import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/ui_components.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'support/fakes.dart';

String key(int value) => base64.encode(List.filled(32, value));
String get original =>
    '[Interface]\r\nPrivateKey = ${key(10)}\r\nAddress = 10.8.0.2/32\r\n'
    '[Peer]\r\nPublicKey = ${key(7)}\r\nPresharedKey = ${key(3)}\r\n'
    'AllowedIPs = 0.0.0.0/0\r\nEndpoint = 203.0.113.10:585\r\n';
const login = ConnectionDetails(
  host: '203.0.113.10',
  port: 22,
  user: 'root',
  password: 'test-session-placeholder',
);

Future<void> connect(Harness h) async {
  h.server.state['external_awg'] = [
    {'source': 'amnezia-awg2', 'running': true},
  ];
  await h.vm.connect(login, (_, _) async => true);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'client keys are parsed from their section without altering original CRLF',
    () {
      final config = ClientConfiguration(original);
      expect(config.content, original);
      expect(config.privateKey, key(10));
      expect(config.secrets, containsAll([key(10), key(3)]));
      expect(ClientConfiguration('\ufeff$original').privateKey, key(10));
      expect(
        ClientConfiguration('[Peer]\nPrivateKey = ${key(7)}').privateKey,
        isNull,
      );
    },
  );

  test(
    'import errors mask original secrets in both visible errors and logs',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      h.server.failAction = 'import-client';
      h.server.failureMessage = 'Rejected ${key(10)} ${key(3)}';
      expect(
        await h.vm.importClientConfiguration(
          'Phone',
          original,
          source: 'amnezia-awg2',
          publicKey: key(2),
        ),
        isFalse,
      );
      for (final secret in [key(10), key(3)]) {
        expect(h.vm.error, isNot(contains(secret)));
        expect(h.vm.log, isNot(contains(secret)));
      }
    },
  );

  test(
    'successful revocation keeps a private-file cleanup warning visible',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      h.server.revokeWarning = 'Private export cleanup is pending.';
      expect(
        await h.vm.revokeClient(
          'Phone',
          source: 'amnezia-awg2',
          publicKey: key(2),
        ),
        isTrue,
      );
      expect(h.vm.message, contains('revoked'));
      expect(h.vm.message, contains('cleanup is pending'));
    },
  );

  testWidgets(
    'reopen the same existing QR and copy its original private key without creating peers',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 1400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      String? copied;
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        (call) async {
          if (call.method == 'Clipboard.setData') {
            copied = (call.arguments as Map)['text'] as String;
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
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.configuration = original;
      h.server.clientRows = [
        {
          'name': 'Phone',
          'source': 'amnezia-awg2',
          'public_key': key(2),
          'can_export': true,
          'can_revoke': true,
        },
      ];
      await connect(h);
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Clients'));
      await tester.pumpAndSettle();
      for (var attempt = 0; attempt < 2; attempt++) {
        await tester.tap(find.widgetWithText(OutlinedButton, 'Show QR code'));
        await tester.pumpAndSettle();
        expect(
          tester
              .widget<ClientExportDialog>(find.byType(ClientExportDialog))
              .config,
          original,
        );
        expect(find.byType(QrImageView), findsOneWidget);
        expect(find.textContaining(key(10)), findsNothing);
        await tester.tap(find.byTooltip('Copy private key'));
        await tester.pumpAndSettle();
        expect(copied, key(10));
        await tester.tap(find.widgetWithText(TextButton, 'Close'));
        await tester.pumpAndSettle();
      }
      expect(h.server.calls.where((c) => c.$1 == 'get-client'), hasLength(2));
      expect(
        h.server.calls.any(
          (c) => {'add-client', 'import-client'}.contains(c.$1),
        ),
        isFalse,
      );
    },
  );

  testWidgets(
    'an imported old configuration stays hidden and unlocks later access',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 1400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        (call) async {
          if (call.method == 'Clipboard.getData') return {'text': original};
          return null;
        },
      );
      addTearDown(
        () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
          SystemChannels.platform,
          null,
        ),
      );
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.clientRows = [
        {
          'name': 'Old phone',
          'source': 'amnezia-awg2',
          'public_key': key(2),
          'can_export': false,
          'can_import': true,
          'can_revoke': true,
        },
      ];
      await connect(h);
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Clients'));
      await tester.pumpAndSettle();
      await tester.tap(
        find.widgetWithText(OutlinedButton, 'Import existing .conf'),
      );
      await tester.pumpAndSettle();
      await tester.tap(
        find.widgetWithText(OutlinedButton, 'Paste configuration'),
      );
      await tester.pumpAndSettle();
      expect(find.textContaining(key(10)), findsNothing);
      await tester.tap(
        find.widgetWithText(FilledButton, 'Save existing configuration'),
      );
      await tester.pumpAndSettle();
      expect(h.server.configuration, original);
      expect(h.server.calls.firstWhere((c) => c.$1 == 'import-client').$2, [
        'Old phone',
        'amnezia-awg2',
        key(2),
        original,
        'no',
      ]);
      expect(h.server.calls.any((c) => c.$1 == 'add-client'), isFalse);
    },
  );

  testWidgets('oversized QR retains copy and file access with an explanation', (
    tester,
  ) async {
    final oversized = '$original\n# ${List.filled(6000, 'x').join()}';
    await tester.pumpWidget(
      AshappApp(
        home: Scaffold(
          body: ClientExportDialog(
            name: 'Existing phone',
            config: oversized,
            initialQr: true,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.textContaining('too large for a QR code'), findsOneWidget);
    expect(find.byTooltip('Copy configuration'), findsOneWidget);
    expect(find.text('Save .conf'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
