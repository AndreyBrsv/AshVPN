import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:ashapp/setup_wizard.dart';
import 'package:ashapp/ui_components.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

void main() {
  Future<void> connect(Harness h) => h.vm.connect(
    const ConnectionDetails(
      host: '203.0.113.10',
      port: 22,
      user: 'root',
      password: 'test-session-placeholder',
    ),
    (_, _) async => true,
  );

  for (final size in [const Size(420, 480), const Size(520, 760)]) {
    testWidgets('all pages remain reachable at $size with large text', (
      tester,
    ) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      tester.platformDispatcher.textScaleFactorTestValue = 1.5;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.state.addAll({
        'awg': true,
        'awg_configured': true,
        'interface': 'awg0',
        'vless': true,
        'vless_configured': true,
        'vless_port': 443,
        'socks5': true,
      });
      h.server.clients.add('Family phone');
      h.server.users.add('administrator');
      await connect(h);
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      for (final (label, heading) in [
        ('Templates', 'Setup templates'),
        ('Manage', 'Server overview'),
        ('Clients', 'VPN clients'),
        ('Access', 'Connection details'),
        ('Servers', 'Your servers'),
      ]) {
        await tester.tap(find.text(label).last);
        await tester.pumpAndSettle();
        expect(find.text('203.0.113.10:22'), findsWidgets);
        expect(find.text(heading), findsOneWidget);
        expect(tester.takeException(), isNull);
        // Reach the lower sections as well as the first card.
        final scroll = find.byType(SingleChildScrollView).first;
        await tester.drag(scroll, const Offset(0, -3000));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      }
      expect(h.vm.connected, isTrue);
    });
  }

  testWidgets('resizing keeps the selected page and connected server', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connect(h);
    await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Templates'));
    await tester.pumpAndSettle();
    final state = tester.state(find.byType(HomePage));
    final backend = h.backends.single;
    for (final size in [
      const Size(520, 760),
      const Size(1000, 720),
      const Size(1280, 800),
      const Size(420, 480),
    ]) {
      tester.view.physicalSize = size;
      await tester.pumpAndSettle();
      expect(find.text('Setup templates'), findsOneWidget);
      expect(tester.state(find.byType(HomePage)), same(state));
      expect(h.vm.connected, isTrue);
      expect(backend.closed, isFalse);
      expect(
        find.byType(NavigationBar),
        size.width < 900 ? findsOneWidget : findsNothing,
      );
      expect(tester.takeException(), isNull);
    }
  });

  testWidgets('template wizard fits the minimum window through every step', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(420, 480);
    tester.view.devicePixelRatio = 1;
    tester.platformDispatcher.textScaleFactorTestValue = 1.5;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final h = Harness();
    addTearDown(h.vm.dispose);
    await tester.pumpWidget(
      AshappApp(
        home: SetupWizard(
          controller: h.vm,
          editTemplate: true,
          secrets: const SetupSecrets(
            adminName: 'administrator',
            adminPassword: 'test-administrator-placeholder',
          ),
          initial: ServerTemplate(
            name: 'Friends',
            blockPing: true,
            disableRoot: false,
            installAwg: true,
            installVless: true,
            installSocks: false,
            awgPort: 585,
            clientNames: ['phone'],
            vlessClientNames: ['laptop'],
          ),
        ),
      ),
    );
    for (var step = 0; step < 5; step++) {
      expect(tester.takeException(), isNull);
      await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
      await tester.pumpAndSettle();
    }
    expect(find.text('Review your answers'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('copy icon exports the existing client without showing keys', (
    tester,
  ) async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.server.configuration = 'private-client-test-placeholder';
    h.server.clientRows = [
      {
        'name': 'Phone',
        'source': 'awg0',
        'public_key': 'public-client-test-placeholder',
        'can_export': true,
      },
    ];
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
    await connect(h);
    await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Clients'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byTooltip('Copy connection'));
    await tester.tap(find.byTooltip('Copy connection'));
    await tester.pumpAndSettle();
    expect(copied, 'private-client-test-placeholder');
    expect(
      find.textContaining('private-client-test-placeholder'),
      findsNothing,
    );
    expect(find.byType(ClientExportDialog), findsNothing);
    final reads = h.server.calls.where((call) => call.$1 == 'get-client');
    expect(reads.single.$2, [
      'Phone',
      'awg0',
      'public-client-test-placeholder',
    ]);
    expect(h.server.calls.any((call) => call.$1 == 'add-client'), isFalse);
    expect(tester.takeException(), isNull);
  });
}
