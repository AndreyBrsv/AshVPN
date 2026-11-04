import 'package:ashapp/connection_details.dart';
import 'package:ashapp/security_panel.dart';
import 'package:ashapp/setup_wizard.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:ashapp/ssh_identity.dart';
import 'package:ashapp/workspace_controller.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

void main() {
  testWidgets(
    'a connected-server template retains its explicitly imported key',
    (tester) async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(
        const ConnectionDetails(
          host: '203.0.113.10',
          port: 22,
          user: 'alice',
          password: 'test-ui-placeholder',
        ),
        (_, _) async => true,
      );
      final key = SshIdentity.generate().privateKey;
      await tester.pumpWidget(
        MaterialApp(
          home: SetupWizard(
            controller: h.vm,
            useConnected: true,
            initial: ServerTemplate(
              name: 'Key import',
              blockPing: false,
              disableRoot: false,
              installAwg: false,
              installSocks: false,
              awgPort: 585,
              clientNames: [],
              createAdmin: false,
            ),
            secrets: SetupSecrets(sshPrivateKey: key),
          ),
        ),
      );
      await tester.tap(find.text('Continue'));
      await tester.pumpAndSettle();
      final input = find.byWidgetPredicate(
        (widget) =>
            widget is TextField &&
            widget.decoration?.labelText ==
                'SSH private key to install (optional)',
      );
      expect(input, findsOneWidget);
      expect(tester.widget<TextField>(input).controller!.text == key, isTrue);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
  Future<void> render(WidgetTester tester, WorkspaceController vm) =>
      tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: ListenableBuilder(
                listenable: vm,
                builder: (_, _) => SecurityPanel(controller: vm),
              ),
            ),
          ),
        ),
      );

  testWidgets(
    'unknown checks cannot be edited and cancelling a preview makes no changes',
    (tester) async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(
        const ConnectionDetails(
          host: '203.0.113.10',
          port: 22,
          user: 'alice',
          password: 'test-ui-placeholder',
        ),
        (_, _) async => true,
      );
      h.vm.security = null;
      await render(tester, h.vm);
      for (final checkbox in tester.widgetList<CheckboxListTile>(
        find.byType(CheckboxListTile),
      )) {
        expect(checkbox.value, isNull);
        expect(checkbox.onChanged, isNull);
      }
      await h.vm.diagnoseSecurity();
      await tester.pumpAndSettle();
      await tester.tap(find.text('Protect SSH with Fail2ban'));
      await tester.pump();
      expect(h.server.calls.where((c) => c.$1 == 'security-stage'), isEmpty);
      await tester.ensureVisible(find.text('Review and apply changes'));
      await tester.tap(find.text('Review and apply changes'));
      await tester.pumpAndSettle();
      expect(find.text('Apply security changes?'), findsOneWidget);
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      expect(h.server.calls.where((c) => c.$1 == 'security-stage'), isEmpty);
      expect(h.server.pendingSecurity, isNull);
    },
  );

  testWidgets('compact security controls keep imported private keys masked', (
    tester,
  ) async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(
      const ConnectionDetails(
        host: '203.0.113.10',
        port: 2222,
        user: 'alice',
        password: 'test-ui-placeholder',
      ),
      (_, _) async => true,
    );
    tester.view.physicalSize = const Size(420, 600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await render(tester, h.vm);
    final input = find.byWidgetPredicate(
      (widget) =>
          widget is TextField &&
          widget.decoration?.labelText == 'Import SSH private key (paste)',
    );
    await tester.ensureVisible(input);
    final pem = SshIdentity.generate().privateKey;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async => call.method == 'Clipboard.getData' ? {'text': pem} : null,
    );
    addTearDown(
      () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        null,
      ),
    );
    await tester.tap(find.byTooltip('Paste SSH private key'));
    await tester.pumpAndSettle();
    expect(tester.widget<TextField>(input).obscureText, isTrue);
    expect(tester.widget<TextField>(input).controller!.text == pem, isTrue);
    expect(
      SshIdentity.parse(
        tester.widget<TextField>(input).controller!.text,
        '',
      ).publicKey.startsWith('ssh-ed25519 '),
      isTrue,
    );
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
