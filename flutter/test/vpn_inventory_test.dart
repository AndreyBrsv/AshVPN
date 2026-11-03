import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/server_workspace.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_secrets.dart';
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
    'different servers keep external clients and discovery warnings isolated',
    () async {
      final h = Harness();
      final workspace = ServerWorkspace(h.vm);
      addTearDown(workspace.dispose);
      h.server.clients.add('First server phone');
      h.server.clientWarnings = ['First server warning'];
      await h.vm.connect(login, (_, _) async => true);
      final second = workspace.create();
      await second.connect(
        const ConnectionDetails(
          host: '203.0.113.20',
          port: 22,
          user: 'root',
          password: 'test-second-placeholder',
        ),
        (_, _) async => true,
      );
      expect(second.clients, isEmpty);
      expect(second.clientWarnings, isEmpty);
      expect(h.vm.clients.single['name'], 'First server phone');
      expect(h.vm.clientWarnings, ['First server warning']);
    },
  );
  test(
    'saved and external clients load without a running host kernel interface',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.clients.add('Existing phone');
      expect(await h.vm.connect(login, (_, _) async => true), isTrue);
      expect(h.vm.server['kernel'], isFalse);
      expect(h.vm.clients.single['name'], 'Existing phone');
      expect(h.server.calls.any((c) => c.$1 == 'clients'), isTrue);
    },
  );

  test('client read failure clears stale rows and does not prevent Linux account refresh', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.server.clients.add('Existing phone');
    await h.vm.connect(login, (_, _) async => true);
    h.server.users.add('administrator');
    h.server.failAction = 'clients';
    await h.vm.refresh();
    expect(h.vm.clients, isEmpty);
    expect(h.vm.clientsError, contains('could not be loaded'));
    expect(h.vm.users.single['name'], 'administrator');
    h.server.failAction = null;
    await h.vm.refresh();
    expect(h.vm.clients.single['name'], 'Existing phone');
    expect(h.vm.clientsError, isEmpty);
  });

  test(
    'external deployment stops kernel setup before account and VPN changes',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.state['external_awg'] = [
        {'source': 'amnezia-awg', 'running': true},
      ];
      await h.vm.connect(login, (_, _) async => true);
      expect(
        await h.vm.provision(
          ServerTemplate(
            name: 'Install',
            blockPing: false,
            disableRoot: false,
            installAwg: true,
            installSocks: false,
            awgPort: 585,
            clientNames: [],
            createAdmin: true,
          ),
          const SetupSecrets(
            adminName: 'admin',
            adminPassword: 'test-admin-placeholder',
          ),
        ),
        isFalse,
      );
      expect(h.vm.error, contains('will not replace'));
      expect(
        h.server.calls.where(
          (c) => {
            'create-user',
            'prepare-awg',
            'install-awg-configured',
          }.contains(c.$1),
        ),
        isEmpty,
      );
    },
  );

  testWidgets(
    'Amnezia clients show source and allow creation while unavailable exports stay disabled',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 1200);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.state['external_awg'] = [
        {'source': 'amnezia-awg', 'running': true},
      ];
      h.server.clientRows = [
        {
          'name': 'Existing phone',
          'source': 'amnezia-awg',
          'addresses': '10.8.0.2/32',
          'handshake': 0,
          'can_export': false,
          'can_revoke': false,
        },
      ];
      await h.vm.connect(login, (_, _) async => true);
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Clients'));
      await tester.pumpAndSettle();
      expect(find.text('Existing phone'), findsOneWidget);
      expect(find.textContaining('amnezia-awg · 10.8.0.2/32'), findsOneWidget);
      expect(find.textContaining('No VPN clients found'), findsNothing);
      expect(
        tester
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Create client'),
            )
            .onPressed,
        isNotNull,
      );
      expect(
        tester
            .widget<OutlinedButton>(
              find.widgetWithText(OutlinedButton, 'Get configuration'),
            )
            .onPressed,
        isNull,
      );
      expect(
        tester
            .widget<TextButton>(
              find.widgetWithText(TextButton, 'Revoke access'),
            )
            .onPressed,
        isNull,
      );
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'failed client read explains the error instead of a successful empty state',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 1200);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.failAction = 'clients';
      await h.vm.connect(login, (_, _) async => true);
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Clients'));
      await tester.pumpAndSettle();
      expect(
        find.textContaining('The VPN client list could not be loaded.'),
        findsOneWidget,
      );
      expect(find.textContaining('No VPN clients found'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );
}
