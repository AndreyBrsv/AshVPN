import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/server_installation_panel.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

void main() {
  void compact(WidgetTester tester) {
    tester.view.physicalSize = const Size(420, 480);
    tester.view.devicePixelRatio = 1;
    tester.platformDispatcher.textScaleFactorTestValue = 1.5;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
  }

  testWidgets('failed setup details and resume reflow with enlarged text', (
    tester,
  ) async {
    compact(tester);
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.vm.installation = {
      'run_id': 'synthetic-run',
      'status': 'failed',
      'steps': {
        'administrator': {'state': 'done'},
        'security': {'state': 'failed'},
      },
      'events': [
        {'step': 'administrator', 'state': 'done', 'time': 1},
        {'step': 'security', 'state': 'failed', 'time': 2},
      ],
    };
    h.vm.inspectionWarnings.add(
      'A synthetic inspection warning with enough detail to wrap onto several lines.',
    );
    h.vm.diagnosticChecks = [
      {
        'id': 'ssh-protection',
        'status': 'fail',
        'detail':
            'The requested protection differs from the actual policy. '
            'Review the full diagnostics before retrying this setup step.',
      },
    ];
    var resumed = false;
    await tester.pumpWidget(
      AshappApp(
        home: Scaffold(
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: ServerInstallationPanel(
              controller: h.vm,
              onResume: () => resumed = true,
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final resume = find.widgetWithText(
      FilledButton,
      'Resume interrupted setup',
    );
    await tester.ensureVisible(resume);
    await tester.tap(resume);
    expect(resumed, isTrue);
    for (final title in ['Recorded setup steps', 'Recent server activity']) {
      await tester.ensureVisible(find.text(title));
      await tester.tap(find.text(title));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    }
    final check = find.text('ssh-protection · fail');
    await tester.ensureVisible(check);
    await tester.pumpAndSettle();
    expect(check.hitTestable(), findsOneWidget);
    final reset = find.widgetWithText(OutlinedButton, 'Review server reset');
    await tester.ensureVisible(reset);
    await tester.pumpAndSettle();
    expect(reset.hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'compact reset review keeps confirmation visible and cancels safely',
    (tester) async {
      compact(tester);
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(
        const ConnectionDetails(
          host: '203.0.113.10',
          port: 22,
          user: 'administrator',
          password: 'synthetic-placeholder',
        ),
        (_, _) async => true,
      );
      await tester.pumpWidget(
        AshappApp(
          home: Scaffold(
            body: SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: ServerInstallationPanel(controller: h.vm, onResume: () {}),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final reset = find.widgetWithText(OutlinedButton, 'Review server reset');
      await tester.ensureVisible(reset);
      await tester.tap(reset);
      await tester.pumpAndSettle();
      expect(find.text('Remove Ashapp server configuration?'), findsOneWidget);
      expect(
        find.widgetWithText(FilledButton, 'Remove configuration').hitTestable(),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
      await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
      await tester.pumpAndSettle();
      expect(h.server.calls.any((call) => call.$1 == 'reset'), isFalse);
      expect(
        h.server.calls.any((call) => call.$1 == 'security-reset-stage'),
        isFalse,
      );
      expect(tester.takeException(), isNull);
    },
  );
}
