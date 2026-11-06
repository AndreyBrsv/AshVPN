import 'package:ashapp/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ashapp/credentials_card.dart';
import 'package:ashapp/connection_details.dart';
import 'package:ashapp/setup_wizard.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:ashapp/ui_components.dart';

import 'support/fakes.dart';

void main() {
  testWidgets(
    'unsupported private SOCKS5 stays stoppable and can be explicitly replaced',
    (tester) async {
      tester.view.physicalSize = const Size(1200, 1600);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.state.addAll({
        'socks5': true,
        'socks5_configured': true,
        'socks5_access': 'private',
        'socks5_private_supported': false,
        'socks5_access_warning':
            'Private SOCKS5 requires Docker Engine 28.0.0 or newer.',
      });
      await h.vm.connect(
        const ConnectionDetails(
          host: '203.0.113.10',
          port: 22,
          user: 'root',
          password: 'test-ui-placeholder',
        ),
        (_, _) async => true,
      );
      h.server.calls.clear();
      h.server.failAction = 'socks-info';
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Manage'));
      await tester.pumpAndSettle();
      expect(
        find.textContaining('Private SOCKS5 requires Docker Engine 28'),
        findsOneWidget,
      );
      final start = find.widgetWithText(
        OutlinedButton,
        'Start private SOCKS5 tunnel',
      );
      expect(tester.widget<OutlinedButton>(start).onPressed, isNull);
      expect(find.textContaining('server loopback only'), findsNothing);
      final replace = find.text('Manage SOCKS5 proxy');
      await tester.ensureVisible(replace);
      await tester.tap(replace);
      await tester.pumpAndSettle();
      expect(find.text('Replace SOCKS5 proxy'), findsOneWidget);
      expect(h.server.calls.where((call) => call.$1 == 'socks-info'), isEmpty);
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'connecting a second server retains the first session and switching restores its view',
    (tester) async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(
        const ConnectionDetails(
          host: '203.0.113.10',
          port: 22,
          user: 'root',
          password: 'test-first-placeholder',
        ),
        (_, _) async => true,
      );
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Connect to existing'));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Server IP address'),
        '203.0.113.20',
      );
      await tester.enterText(
        find.widgetWithText(TextFormField, 'Password'),
        'test-second-placeholder',
      );
      await tester.tap(find.widgetWithText(FilledButton, 'Connect'));
      await tester.pumpAndSettle();
      expect(find.text('203.0.113.20:22'), findsOneWidget);
      expect(h.vm.connected, isTrue);
      expect(h.backends.where((b) => !b.closed), hasLength(2));
      await tester.tap(find.byTooltip('Switch server'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('203.0.113.10:22 · Connected'));
      await tester.pumpAndSettle();
      expect(find.text('203.0.113.10:22'), findsWidgets);
      expect(h.vm.ssh!.password, 'test-first-placeholder');
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('loading another template resets password visibility', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1200, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final h = Harness();
    addTearDown(h.vm.dispose);
    ServerTemplate item(String name) => ServerTemplate(
      name: name,
      blockPing: false,
      disableRoot: false,
      installAwg: false,
      installSocks: false,
      awgPort: 585,
      clientNames: [],
    );
    await h.vm.saveTemplate(
      item('First'),
      const SetupSecrets(connectionPassword: 'test-first-placeholder'),
    );
    await h.vm.saveTemplate(
      item('Second'),
      const SetupSecrets(connectionPassword: 'test-second-placeholder'),
    );
    await tester.pumpWidget(
      AshappApp(
        home: SetupWizard(
          controller: h.vm,
          initial: h.vm.templates.firstWhere((t) => t.name == 'First'),
          secrets: const SetupSecrets(
            connectionPassword: 'test-first-placeholder',
          ),
        ),
      ),
    );
    await tester.tap(find.byTooltip('Show password'));
    await tester.pump();
    expect(
      tester.widget<TextField>(find.byType(TextField).last).obscureText,
      isFalse,
    );
    await tester.tap(find.byType(DropdownButtonFormField<String>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Template · Second').last);
    await tester.pumpAndSettle();
    expect(
      tester.widget<TextField>(find.byType(TextField).last).obscureText,
      isTrue,
    );
    expect(find.byTooltip('Hide password'), findsNothing);
  });

  testWidgets(
    'review runs the complete wizard and shows masked connection results',
    (tester) async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(
        const ConnectionDetails(
          host: '203.0.113.10',
          port: 22,
          user: 'root',
          password: 'test-session-placeholder',
        ),
        (_, _) async => true,
      );
      await tester.pumpWidget(
        AshappApp(
          home: SetupWizard(
            controller: h.vm,
            useConnected: true,
            initial: ServerTemplate(
              name: 'Full setup',
              blockPing: true,
              disableRoot: true,
              installAwg: true,
              installSocks: true,
              awgPort: 585,
              clientNames: ['phone'],
            ),
            secrets: const SetupSecrets(
              adminName: 'alice',
              adminPassword: 'test-admin-placeholder',
              socksUser: 'proxy',
              socksPassword: 'test_proxy_placeholder',
            ),
          ),
        ),
      );
      for (var i = 0; i < 5; i++) {
        await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
        await tester.pumpAndSettle();
      }
      expect(h.server.state['awg'], isFalse);
      await tester.tap(find.widgetWithText(FilledButton, 'Run setup'));
      await tester.runAsync(() async => Future<void>.delayed(Duration.zero));
      await tester.pumpAndSettle();
      expect(h.vm.setupComplete, isTrue);
      expect(find.text('Your server is ready'), findsOneWidget);
      expect(find.textContaining('test-admin-placeholder'), findsNothing);
      expect(find.textContaining('test_proxy_placeholder'), findsNothing);
      expect(h.vm.clients.single['name'], 'phone');
      expect(tester.takeException(), isNull);
    },
  );
  testWidgets('connection form rejects missing values', (tester) async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Connect to existing'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Connect'));
    await tester.pump();
    expect(
      find.text('Enter the address, port, username and password.'),
      findsWidgets,
    );
    expect(h.logins, isEmpty);
  });

  testWidgets(
    'template editor prefills every step and saves protected answers',
    (tester) async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      final template = ServerTemplate(
        name: 'Friends',
        blockPing: true,
        disableRoot: true,
        installAwg: true,
        installSocks: true,
        awgPort: 585,
        socksPort: 1081,
        changeRootPassword: true,
        clientNames: ['phone', 'laptop'],
      );
      await tester.pumpWidget(
        AshappApp(
          home: SetupWizard(
            controller: h.vm,
            editTemplate: true,
            initial: template,
            secrets: const SetupSecrets(
              adminName: 'alice',
              adminPassword: 'test-admin-placeholder',
              rootPassword: 'test-root-placeholder',
              socksUser: 'proxy',
              socksPassword: 'test_proxy_placeholder',
            ),
          ),
        ),
      );
      for (var i = 0; i < 5; i++) {
        await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
        await tester.pumpAndSettle();
      }
      expect(find.text('Review your answers'), findsOneWidget);
      expect(
        find.text('Install SOCKS5: Yes · TCP 1081 · public'),
        findsOneWidget,
      );
      expect(find.textContaining('test-admin-placeholder'), findsNothing);
      await tester.tap(find.widgetWithText(FilledButton, 'Save template'));
      await tester.pumpAndSettle();
      expect(h.vm.templates.single.installSocks, isTrue);
      expect(h.vm.templates.single.clientNames, ['phone', 'laptop']);
      expect((await h.vm.templateSecrets('Friends')).adminName, 'alice');
      expect(h.logins, isEmpty);
    },
  );

  testWidgets('credentials are masked until explicitly revealed', (
    tester,
  ) async {
    await tester.pumpWidget(
      const AshappApp(
        home: Scaffold(
          body: CredentialsCard(
            title: 'SSH',
            details: ConnectionDetails(
              host: '203.0.113.10',
              port: 22,
              user: 'alice',
              password: 'test-credential-placeholder',
            ),
          ),
        ),
      ),
    );
    expect(find.text('test-credential-placeholder'), findsNothing);
    await tester.tap(find.text('Show password'));
    await tester.pump();
    expect(find.textContaining('test-credential-placeholder'), findsOneWidget);
  });

  testWidgets(
    'private client export offers copy and QR without revealing text',
    (tester) async {
      await tester.pumpWidget(
        const AshappApp(
          home: Scaffold(
            body: ClientExportDialog(
              name: 'phone',
              config: 'private-config-test-placeholder',
            ),
          ),
        ),
      );
      expect(find.text('private-config-test-placeholder'), findsNothing);
      expect(find.text('Show configuration'), findsNothing);
      expect(find.byTooltip('Copy configuration'), findsOneWidget);
      await tester.tap(find.text('Show QR code'));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('compact navigation stays usable with large text', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(480, 700);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final h = Harness();
    addTearDown(h.vm.dispose);
    await tester.pumpWidget(
      AshappApp(
        home: MediaQuery(
          data: const MediaQueryData(textScaler: TextScaler.linear(1.5)),
          child: HomePage(controller: h.vm),
        ),
      ),
    );
    await tester.pumpAndSettle();
    for (final icon in [
      Icons.auto_awesome_mosaic_outlined,
      Icons.tune,
      Icons.devices,
      Icons.key_outlined,
      Icons.dns_outlined,
    ]) {
      await tester.tap(find.byIcon(icon).last);
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    }
  });
}
