import 'dart:io';

import 'package:ashapp/activity_console.dart';
import 'package:ashapp/app_update.dart';
import 'package:ashapp/app_update_dialog.dart';
import 'package:ashapp/appearance.dart';
import 'package:ashapp/appearance_dialog.dart';
import 'package:ashapp/connection_details.dart';
import 'package:ashapp/create_client_dialog.dart';
import 'package:ashapp/import_client_dialog.dart';
import 'package:ashapp/json_file_store.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/private_qr.dart';
import 'package:ashapp/server_profiles.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_wizard.dart';
import 'package:ashapp/ui_components.dart';
import 'package:ashapp/vless_connection.dart';
import 'package:ashapp/vless_export_dialog.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'support/fakes.dart';

class _IdleUpdateRuntime extends Fake implements UpdateRuntime {}

class _IdleUpdateTransport extends Fake implements UpdateTransport {}

const _nativeConfig =
    '[Interface]\n'
    'PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n'
    'Address = 10.8.0.2/32\nDNS = 1.1.1.1\n'
    '[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n'
    'Endpoint = 203.0.113.10:585\nAllowedIPs = 0.0.0.0/0\n';

VlessConnection _vlessConnection() => VlessConnection.fromJson({
  'name': 'Existing family phone',
  'uuid': '01234567-89ab-cdef-0123-456789abcdef',
  'address': '203.0.113.10',
  'port': 443,
  'sni': 'example.com',
  'public_key': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  'short_id': '01234567',
  'fingerprint': 'chrome',
  'flow': VlessConnection.flow,
});

void main() {
  void compact(WidgetTester tester) {
    tester.view.physicalSize = const Size(420, 480);
    tester.view.devicePixelRatio = 1;
    tester.platformDispatcher.textScaleFactorTestValue = 1.5;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
  }

  for (final entry in <(String, Widget)>[
    (
      'new client',
      const CreateClientDialog(
        sources: ['awg0', 'amnezia-awg2', VlessConnection.source],
        endpoint: '203.0.113.10:22',
      ),
    ),
    (
      'existing import',
      const ImportClientDialog(
        endpoint: '203.0.113.10:22',
        name: 'Existing family phone',
      ),
    ),
    (
      'Amnezia export',
      const ClientExportDialog(
        name: 'Existing family phone',
        endpoint: '203.0.113.10:22 · awg0',
        config: _nativeConfig,
      ),
    ),
    (
      'VLESS export',
      VlessExportDialog(
        connection: _vlessConnection(),
        endpoint: '203.0.113.10:22',
      ),
    ),
  ]) {
    testWidgets('${entry.$1} dialog fits compact enlarged text', (
      tester,
    ) async {
      compact(tester);
      await tester.pumpWidget(AshappApp(home: Scaffold(body: entry.$2)));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      final action = switch (entry.$1) {
        'new client' => 'Create',
        'existing import' => 'Save existing configuration',
        'Amnezia export' => 'Save .vpn',
        _ => 'Save file',
      };
      expect(
        find.widgetWithText(FilledButton, action).hitTestable(),
        findsOneWidget,
      );
    });
  }

  for (final vless in [false, true]) {
    testWidgets(
      '${vless ? 'VLESS' : 'native'} QR keeps its original data and fits after resizing',
      (tester) async {
        compact(tester);
        final connection = _vlessConnection();
        await tester.pumpWidget(
          AshappApp(
            home: Scaffold(
              body: vless
                  ? VlessExportDialog(
                      connection: connection,
                      endpoint: '203.0.113.10:22',
                      initialQr: true,
                    )
                  : const ClientExportDialog(
                      name: 'Existing family phone',
                      endpoint: '203.0.113.10:22 · awg0',
                      config: _nativeConfig,
                      initialQr: true,
                    ),
            ),
          ),
        );
        for (final size in [
          const Size(420, 480),
          const Size(520, 760),
          const Size(1000, 1000),
        ]) {
          tester.view.physicalSize = size;
          await tester.pumpAndSettle();
          final qr = find.byType(PrivateQr);
          expect(
            tester.widget<PrivateQr>(qr).data,
            vless ? connection.link : _nativeConfig,
          );
          await tester.ensureVisible(qr);
          await tester.pumpAndSettle();
          expect(qr.hitTestable(), findsOneWidget);
          expect(find.byType(QrImageView), findsOneWidget);
          final bounds = tester.getRect(qr);
          expect(bounds.width, bounds.height);
          expect(bounds.width, lessThanOrEqualTo(420));
          expect(bounds.left, greaterThanOrEqualTo(40));
          expect(bounds.right, lessThanOrEqualTo(size.width - 40));
          expect(
            find
                .widgetWithText(
                  FilledButton,
                  vless ? 'Save file' : 'Save .conf',
                )
                .hitTestable(),
            findsOneWidget,
          );
          expect(tester.takeException(), isNull);
        }
      },
    );
  }

  testWidgets('key connection form scrolls while its action stays reachable', (
    tester,
  ) async {
    compact(tester);
    final h = Harness();
    addTearDown(h.vm.dispose);
    await tester.pumpWidget(
      AshappApp(
        home: Scaffold(
          body: ConnectDialog(
            controller: h.vm,
            profile: const ServerProfile(ip: '203.0.113.10', sshPort: 22),
            saved: const ConnectionDetails(
              host: '203.0.113.10',
              port: 22,
              user: 'administrator',
              password: '',
              privateKey: 'synthetic-unparsed-key-placeholder',
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final passphrase = find.byWidgetPredicate(
      (widget) =>
          widget is TextField &&
          widget.decoration?.labelText == 'Key passphrase (optional)',
    );
    await tester.ensureVisible(passphrase);
    await tester.pumpAndSettle();
    expect(passphrase.hitTestable(), findsOneWidget);
    expect(find.byTooltip('Show password').hitTestable(), findsOneWidget);
    expect(
      find.widgetWithText(FilledButton, 'Connect').hitTestable(),
      findsOneWidget,
    );
    final key = tester
        .widgetList<EditableText>(find.byType(EditableText))
        .singleWhere(
          (field) =>
              field.controller.text == 'synthetic-unparsed-key-placeholder',
        );
    expect(key.obscureText, isTrue);
    expect(key.readOnly, isTrue);
    expect(tester.takeException(), isNull);
  });

  testWidgets('multi-field account dialog scrolls without losing actions', (
    tester,
  ) async {
    compact(tester);
    await tester.pumpWidget(
      const AshappApp(
        home: Scaffold(
          body: ValuesDialog(
            title: 'Create an administrator account',
            description:
                'Create a regular Linux account with passwordless sudo. '
                'The existing administrator password is replaced if this username already exists. '
                'Keep a protected recovery copy of the new credentials.',
            fields: [
              InputSpec('Administrator username'),
              InputSpec('New administrator password', secret: true),
              InputSpec('Confirm administrator password', secret: true),
            ],
            action: 'Create administrator',
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final lastField = find.byType(TextFormField).last;
    await tester.ensureVisible(lastField);
    await tester.pumpAndSettle();
    expect(lastField.hitTestable(), findsOneWidget);
    expect(
      find.widgetWithText(FilledButton, 'Create administrator').hitTestable(),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('appearance choices scroll and remain selectable', (
    tester,
  ) async {
    compact(tester);
    final appearance = AppearanceController();
    addTearDown(appearance.dispose);
    await tester.pumpWidget(
      AshappApp(
        appearance: appearance,
        home: Scaffold(body: AppearanceDialog(controller: appearance)),
      ),
    );
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Dark'));
    await tester.pumpAndSettle();
    expect(find.text('Dark').hitTestable(), findsOneWidget);
    await tester.tap(find.text('Dark'));
    await tester.pumpAndSettle();
    expect(appearance.mode, ThemeMode.dark);
    expect(
      find.widgetWithText(TextButton, 'Done').hitTestable(),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('updates status scrolls and keeps check and close visible', (
    tester,
  ) async {
    compact(tester);
    final h = Harness();
    addTearDown(h.vm.dispose);
    final updates =
        AppUpdateController(
            repository: UpdateRepository(
              transport: _IdleUpdateTransport(),
              cache: Directory('unused-layout-update-cache'),
            ),
            runtime: _IdleUpdateRuntime(),
            preferences: JsonFileStore(
              File('unused-layout-update-preferences.json'),
            ),
          )
          ..platform = UpdatePlatform(
            version: AppVersion.parse('0.0.12'),
            target: 'windows-x64',
          )
          ..notice = 'No newer stable release is available.'
          ..error =
              'Synthetic network status: a new check can be requested after '
              'the current connection becomes available.';
    addTearDown(updates.dispose);
    await tester.pumpWidget(
      AshappApp(
        home: Scaffold(
          body: AppUpdateDialog(
            controller: updates,
            workspace: h.vm,
            canInstall: () => true,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.ensureVisible(
      find.textContaining('Downloads are checked against GitHub SHA-256'),
    );
    await tester.pumpAndSettle();
    expect(
      find.widgetWithText(OutlinedButton, 'Check now').hitTestable(),
      findsOneWidget,
    );
    expect(
      find.widgetWithText(TextButton, 'Close').hitTestable(),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('activity dialog scrolls its content and keeps close reachable', (
    tester,
  ) async {
    compact(tester);
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.vm.ssh = const ConnectionDetails(
      host: '203.0.113.10',
      port: 22,
      user: 'administrator',
      password: '',
    );
    h.vm.log = List.generate(
      60,
      (index) => 'Synthetic package step $index',
    ).join('\n');
    h.vm.message =
        'The local activity details remain available after this '
        'synthetic operation ends.';
    await tester.pumpWidget(
      AshappApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => TextButton(
              onPressed: () => showActivityConsole(context, h.vm),
              child: const Text('Open activity'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Open activity'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byTooltip('Copy activity log'));
    await tester.pumpAndSettle();
    expect(find.byTooltip('Copy activity log').hitTestable(), findsOneWidget);
    final close = find.widgetWithText(TextButton, 'Close');
    expect(close.hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.tap(close);
    await tester.pumpAndSettle();
    expect(find.byType(ActivityConsole), findsNothing);
  });

  for (final serverKey in [false, true]) {
    testWidgets(
      '${serverKey ? 'host fingerprint' : 'update confirmation'} remains readable in a compact window',
      (tester) async {
        compact(tester);
        await tester.pumpWidget(
          AshappApp(
            home: Scaffold(
              body: Builder(
                builder: (context) => TextButton(
                  onPressed: () => serverKey
                      ? confirmServerKey(
                          context,
                          'ssh-ed25519',
                          'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                        )
                      : confirmAction(
                          context,
                          'Update to Ashapp 0.0.12?',
                          'Ashapp will close and disconnect all SSH sessions, update in the background and reopen. '
                              'Your saved servers, templates and protected passwords stay on this computer. '
                              'A system security or administrator prompt may still require your approval.',
                          action: 'Restart and update',
                        ),
                  child: const Text('Open dialog'),
                ),
              ),
            ),
          ),
        );
        await tester.tap(find.text('Open dialog'));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets('SOCKS setup stays within a compact window with enlarged text', (
    tester,
  ) async {
    compact(tester);
    final h = Harness();
    addTearDown(h.vm.dispose);
    await tester.pumpWidget(
      AshappApp(
        home: SetupWizard(
          controller: h.vm,
          editTemplate: true,
          initial: ServerTemplate(
            name: 'Layout test',
            blockPing: false,
            disableRoot: false,
            installAwg: false,
            installSocks: true,
            createAdmin: false,
            awgPort: 585,
            clientNames: [],
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    for (var step = 0; step < 3; step++) {
      await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
      await tester.pumpAndSettle();
    }
    expect(find.text('SOCKS5 proxy'), findsOneWidget);
    await tester.ensureVisible(find.text('SOCKS5 access'));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });
}
