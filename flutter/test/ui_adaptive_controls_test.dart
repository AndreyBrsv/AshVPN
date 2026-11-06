import 'package:ashapp/activity_console.dart';
import 'package:ashapp/connection_details.dart';
import 'package:ashapp/create_client_dialog.dart';
import 'package:ashapp/credentials_card.dart';
import 'package:ashapp/import_client_dialog.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/vless_connection.dart';
import 'package:ashapp/vless_export_dialog.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

const _longName =
    'Family laptop with an unusually long device name for shared access';

void main() {
  void window(WidgetTester tester, Size size) {
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1;
    tester.platformDispatcher.textScaleFactorTestValue = 1.5;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
  }

  for (final size in [const Size(900, 480), const Size(1280, 480)]) {
    testWidgets('short wide window keeps navigation reachable at $size', (
      tester,
    ) async {
      window(tester, size);
      final h = Harness();
      addTearDown(h.vm.dispose);
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      final access = find.text('Access').last;
      await tester.ensureVisible(access);
      await tester.pumpAndSettle();
      expect(access.hitTestable(), findsOneWidget);
      await tester.tap(access);
      await tester.pumpAndSettle();
      expect(find.text('Connection details'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets(
    'client source menu can select shared deployment with large text',
    (tester) async {
      window(tester, const Size(420, 480));
      await tester.pumpWidget(
        const AshappApp(
          home: Scaffold(
            body: CreateClientDialog(
              sources: ['awg0', 'amnezia-awg2', VlessConnection.source],
              endpoint: '203.0.113.10:22222',
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byType(DropdownButtonFormField<String>));
      await tester.tap(find.byType(DropdownButtonFormField<String>));
      await tester.pumpAndSettle();
      final shared = find.text(vpnSourceLabel('amnezia-awg2')).last;
      await tester.ensureVisible(shared);
      await tester.tap(shared);
      await tester.pumpAndSettle();
      expect(find.text('Client DNS address'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'VLESS JSON format stays readable after selection at large text',
    (tester) async {
      window(tester, const Size(420, 480));
      final connection = VlessConnection.fromJson({
        'name': _longName,
        'uuid': '01234567-89ab-cdef-0123-456789abcdef',
        'address': '203.0.113.10',
        'port': 443,
        'sni': 'example.com',
        'public_key': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'short_id': '01234567',
        'fingerprint': 'chrome',
        'flow': VlessConnection.flow,
      });
      await tester.pumpWidget(
        AshappApp(
          home: Scaffold(
            body: VlessExportDialog(
              connection: connection,
              endpoint: '203.0.113.10:22222',
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final dropdown = find.byType(DropdownButtonFormField<VlessExportFormat>);
      await tester.ensureVisible(dropdown);
      await tester.tap(dropdown);
      await tester.pumpAndSettle();
      final format = find.text(VlessExportFormat.singBox.label).last;
      await tester.ensureVisible(format);
      await tester.tap(format);
      await tester.pumpAndSettle();
      expect(
        find.widgetWithText(FilledButton, 'Save file').hitTestable(),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('long client import heading keeps its action visible', (
    tester,
  ) async {
    window(tester, const Size(420, 480));
    await tester.pumpWidget(
      const AshappApp(
        home: Scaffold(
          body: ImportClientDialog(
            endpoint: '203.0.113.10:22222',
            name: _longName,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final replace = find.text('Replace saved copy');
    await tester.ensureVisible(replace);
    await tester.pumpAndSettle();
    expect(replace.hitTestable(), findsOneWidget);
    expect(
      find
          .widgetWithText(FilledButton, 'Save existing configuration')
          .hitTestable(),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('credentials actions reflow in compact cards with large text', (
    tester,
  ) async {
    window(tester, const Size(420, 480));
    await tester.pumpWidget(
      const AshappApp(
        home: Scaffold(
          body: SingleChildScrollView(
            padding: EdgeInsets.all(24),
            child: CredentialsCard(
              title: 'Administrator connection details',
              details: ConnectionDetails(
                host: '203.0.113.10',
                port: 22222,
                user: 'administrator',
                password: 'synthetic-placeholder',
              ),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final show = find.widgetWithText(TextButton, 'Show password');
    await tester.ensureVisible(show);
    await tester.tap(show);
    await tester.pumpAndSettle();
    expect(find.textContaining('synthetic-placeholder'), findsOneWidget);
    final copy = find.widgetWithText(TextButton, 'Copy connection details');
    await tester.ensureVisible(copy);
    await tester.pumpAndSettle();
    expect(copy.hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('activity failure details wrap and keep close reachable', (
    tester,
  ) async {
    window(tester, const Size(420, 480));
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.vm.error =
        'The selected setup step failed. Completed steps remain applied. '
        'Run diagnostics to inspect the server and review recovery before retrying.';
    await tester.pumpWidget(
      AshappApp(
        home: Scaffold(
          body: Builder(
            builder: (context) => TextButton(
              onPressed: () => showActivityConsole(context, h.vm),
              child: const Text('Open console'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Open console'));
    await tester.pumpAndSettle();
    final close = find.widgetWithText(TextButton, 'Close');
    expect(close.hitTestable(), findsOneWidget);
    await tester.ensureVisible(find.byTooltip('Copy activity log'));
    await tester.pumpAndSettle();
    expect(close.hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
