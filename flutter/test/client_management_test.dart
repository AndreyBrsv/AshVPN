import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/server_workspace.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

const login = ConnectionDetails(
  host: '203.0.113.10',
  port: 22,
  user: 'root',
  password: 'test-session-placeholder',
);

void main() {
  test(
    'client operations carry source and key and stay on their original server',
    () async {
      final h = Harness();
      final workspace = ServerWorkspace(h.vm);
      addTearDown(workspace.dispose);
      h.server.state['external_awg'] = [
        {'source': 'amnezia-awg', 'running': true},
      ];
      await h.vm.connect(login, (_, _) async => true);
      expect(
        await h.vm.addClient(
          'Phone with spaces',
          source: 'amnezia-awg',
          dns: '9.9.9.9',
        ),
        isTrue,
      );
      final second = workspace.create();
      await second.connect(
        const ConnectionDetails(
          host: '203.0.113.20',
          port: 22,
          user: 'root',
          password: 'test-other-placeholder',
        ),
        (_, _) async => true,
      );
      workspace.select(second);
      expect(
        await h.vm.renameClient(
          'Same name',
          'New name',
          source: 'amnezia-awg',
          publicKey: 'test-public-placeholder',
        ),
        isTrue,
      );
      expect(
        await h.vm.revokeClient(
          'New name',
          source: 'amnezia-awg',
          publicKey: 'test-public-placeholder',
        ),
        isTrue,
      );
      await h.vm.clientConfig(
        'New name',
        source: 'amnezia-awg',
        publicKey: 'test-public-placeholder',
      );
      final calls = h.server.calls;
      expect(calls.firstWhere((c) => c.$1 == 'add-client').$2, [
        'Phone with spaces',
        'amnezia-awg',
        login.host,
        '9.9.9.9',
      ]);
      expect(calls.firstWhere((c) => c.$1 == 'rename-client').$2, [
        'Same name',
        'amnezia-awg',
        'test-public-placeholder',
        'New name',
      ]);
      expect(calls.firstWhere((c) => c.$1 == 'revoke-client').$2, [
        'New name',
        'amnezia-awg',
        'test-public-placeholder',
      ]);
      expect(
        h.servers['203.0.113.20']!.calls.any((c) => c.$1.endsWith('-client')),
        isFalse,
      );
    },
  );

  test(
    'creation rejects a stopped or unknown source without sending a mutation',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login, (_, _) async => true);
      expect(await h.vm.addClient('phone', source: 'amnezia-awg'), isFalse);
      expect(h.server.calls.any((c) => c.$1 == 'add-client'), isFalse);
    },
  );

  testWidgets('create dialog selects one VPN and sends its name and DNS', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.server.state['external_awg'] = [
      {'source': 'amnezia-awg', 'running': true},
      {'source': 'amnezia-awg2', 'running': true},
    ];
    await h.vm.connect(login, (_, _) async => true);
    await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Clients'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Create client'));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(DropdownButtonFormField<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('AmneziaWG · amnezia-awg2').last);
    await tester.pumpAndSettle();
    await tester.enterText(
      find.widgetWithText(TextFormField, 'Client name'),
      'Family phone',
    );
    await tester.enterText(
      find.widgetWithText(TextFormField, 'Client DNS address'),
      '9.9.9.9',
    );
    await tester.tap(find.widgetWithText(FilledButton, 'Create'));
    await tester.pumpAndSettle();
    expect(h.server.calls.firstWhere((c) => c.$1 == 'add-client').$2, [
      'Family phone',
      'amnezia-awg2',
      login.host,
      '9.9.9.9',
    ]);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'rename dialog preserves the exact client identity when names overlap',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 1200);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.state['external_awg'] = [
        {'source': 'amnezia-awg2', 'running': true},
      ];
      h.server.clientRows = [
        {
          'name': 'Phone',
          'source': 'amnezia-awg2',
          'public_key': 'test-second-public-placeholder',
          'can_rename': true,
          'can_revoke': true,
          'can_export': false,
        },
      ];
      await h.vm.connect(login, (_, _) async => true);
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Clients'));
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(TextButton, 'Rename'));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.widgetWithText(TextFormField, 'New client name'),
        'Travel phone',
      );
      await tester.tap(find.widgetWithText(FilledButton, 'Rename'));
      await tester.pumpAndSettle();
      expect(h.server.calls.firstWhere((c) => c.$1 == 'rename-client').$2, [
        'Phone',
        'amnezia-awg2',
        'test-second-public-placeholder',
        'Travel phone',
      ]);
      expect(find.text('Travel phone'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );
}
