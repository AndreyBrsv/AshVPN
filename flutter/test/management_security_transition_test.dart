import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/server_installation_panel.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

void main() {
  testWidgets(
    'applying security after scrolling keeps newly recorded activity visible',
    (tester) async {
      tester.view.physicalSize = const Size(510, 750);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(
        const ConnectionDetails(
          host: '203.0.113.10',
          port: 22,
          user: 'root',
          password: 'synthetic-ui-placeholder',
        ),
        (_, _) async => true,
      );
      await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Manage').last);
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Firewall protection'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Firewall protection'));
      await tester.pump();
      await tester.ensureVisible(find.text('Review and apply changes'));
      await tester.tap(find.text('Review and apply changes'));
      await tester.pumpAndSettle();
      expect(find.text('Apply security changes?'), findsOneWidget);
      // Production records security actions even without an earlier setup run.
      // The resulting refresh introduces a new expansion tile into a page that
      // already has a persisted, nonzero scroll offset.
      h.server.lifecycle['events'] = [
        {'action': 'security-stage', 'state': 'done', 'time': 1},
        {'action': 'security-confirm', 'state': 'done', 'time': 2},
      ];
      h.server.lifecycle['steps'] = {
        'security': {'state': 'done'},
      };
      await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
      await tester.pumpAndSettle();
      expect(
        h.vm.message,
        'Security settings confirmed through a new SSH connection.',
      );
      expect(tester.takeException(), isNull);
      expect(find.byType(ErrorWidget), findsNothing);
      await tester.ensureVisible(find.text('Recent server activity'));
      await tester.tap(find.text('Recent server activity'));
      await tester.pumpAndSettle();
      expect(find.text('security-confirm · done'), findsOneWidget);
      expect(find.text('security'), findsNothing);
      expect(tester.takeException(), isNull);
      // A later visit must restore both a numeric scroll offset and the
      // independent activity expansion state without mixing their types.
      await tester.tap(find.text('Access').last);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Manage').last);
      await tester.pumpAndSettle();
      expect(find.text('security-confirm · done'), findsOneWidget);
      expect(find.text('security'), findsNothing);
      await tester.ensureVisible(find.text('Recorded setup steps'));
      await tester.tap(find.text('Recorded setup steps'));
      await tester.pumpAndSettle();
      expect(find.text('security'), findsOneWidget);
      await tester.ensureVisible(find.text('Recent server activity'));
      await tester.tap(find.text('Recent server activity'));
      await tester.pumpAndSettle();
      expect(find.text('security-confirm · done'), findsNothing);
      expect(find.text('security'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('installation sections retain independent state per server', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(420, 480);
    tester.view.devicePixelRatio = 1;
    tester.platformDispatcher.textScaleFactorTestValue = 1.5;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final first = Harness(), second = Harness();
    addTearDown(first.vm.dispose);
    addTearDown(second.vm.dispose);
    for (final (harness, id) in [(first, 'first'), (second, 'second')]) {
      harness.vm.installation = {
        'status': 'complete',
        'steps': {
          '$id-security': {'state': 'done'},
        },
        'events': [
          {'action': '$id-confirm', 'state': 'done', 'time': 1},
        ],
      };
    }
    var active = first.vm;
    late StateSetter rebuild;
    await tester.pumpWidget(
      AshappApp(
        home: Scaffold(
          body: StatefulBuilder(
            builder: (context, setState) {
              rebuild = setState;
              return SingleChildScrollView(
                key: const PageStorageKey('management-page'),
                padding: const EdgeInsets.all(16),
                child: ServerInstallationPanel(
                  key: ObjectKey(active),
                  controller: active,
                  onResume: () {},
                ),
              );
            },
          ),
        ),
      ),
    );
    await tester.ensureVisible(find.text('Recorded setup steps'));
    await tester.tap(find.text('Recorded setup steps'));
    await tester.pumpAndSettle();
    expect(find.text('first-security'), findsOneWidget);
    expect(find.text('first-confirm · done'), findsNothing);

    rebuild(() => active = second.vm);
    await tester.pumpAndSettle();
    expect(find.text('second-security'), findsNothing);
    expect(find.text('second-confirm · done'), findsNothing);
    await tester.ensureVisible(find.text('Recent server activity'));
    await tester.tap(find.text('Recent server activity'));
    await tester.pumpAndSettle();
    expect(find.text('second-confirm · done'), findsOneWidget);
    expect(find.text('second-security'), findsNothing);

    rebuild(() => active = first.vm);
    await tester.pumpAndSettle();
    expect(find.text('first-security'), findsOneWidget);
    expect(find.text('first-confirm · done'), findsNothing);
    expect(tester.takeException(), isNull);
    expect(find.byType(ErrorWidget), findsNothing);
  });
}
