import 'dart:async';

import 'package:ashapp/activity_console.dart';
import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

Future<void> connect(Harness h, {String host = '203.0.113.10'}) async {
  await h.vm.connect(
    ConnectionDetails(
      host: host,
      port: 22,
      user: 'root',
      password: 'test-console-placeholder',
    ),
    (_, _) async => true,
  );
}

void main() {
  testWidgets('live output and copying use only the session redacted log', (
    tester,
  ) async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connect(h);
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
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: ActivityConsole(controller: h.vm, initiallyExpanded: true),
        ),
      ),
    );
    h.backends.last.output.add('Installing packages: test-console-placeholder');
    await tester.pump();
    expect(
      find.textContaining('Installing packages: ********'),
      findsOneWidget,
    );
    expect(find.textContaining('test-console-placeholder'), findsNothing);
    await tester.tap(find.byTooltip('Copy activity log'));
    await tester.pump();
    expect(copied, contains('Installing packages: ********'));
    expect(copied, isNot(contains('test-console-placeholder')));
    expect(find.text('Activity log copied.'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('failure details remain readable after a command stops', (
    tester,
  ) async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connect(h);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: ActivityConsole(controller: h.vm, initiallyExpanded: true),
        ),
      ),
    );
    h.server.failAction = 'diagnostics';
    h.server.failureMessage = 'Package repository unavailable.';
    await h.vm.diagnoseSecurity();
    await tester.pump();
    expect(find.text('Operation failed · 203.0.113.10:22'), findsOneWidget);
    expect(find.text('Package repository unavailable.'), findsWidgets);
    final copy = tester.widget<IconButton>(
      find.byWidgetPredicate(
        (widget) =>
            widget is IconButton && widget.tooltip == 'Copy activity log',
      ),
    );
    expect(copy.onPressed, isNotNull);
  });

  testWidgets(
    'following can pause without losing the current scroll position',
    (tester) async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 320,
              child: ActivityConsole(
                controller: h.vm,
                initiallyExpanded: true,
                height: 160,
              ),
            ),
          ),
        ),
      );
      h.backends.last.output.add(
        List.generate(80, (i) => 'Package $i').join('\n'),
      );
      await tester.pump();
      await tester.pump();
      final output = tester.widget<SingleChildScrollView>(
        find.byKey(const ValueKey('activity-output')),
      );
      final scroll = output.controller!;
      expect(scroll.offset, scroll.position.maxScrollExtent);
      await tester.tap(find.text('Follow output'));
      await tester.pump();
      scroll.jumpTo(0);
      h.backends.last.output.add('Another package finished.');
      await tester.pump();
      await tester.pump();
      expect(scroll.offset, 0);
      await tester.tap(find.text('Follow output'));
      await tester.pump();
      await tester.pump();
      expect(scroll.offset, scroll.position.maxScrollExtent);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('dialog stays bound to the captured server session', (
    tester,
  ) async {
    final first = Harness(), second = Harness();
    addTearDown(first.vm.dispose);
    addTearDown(second.vm.dispose);
    await connect(first);
    await connect(second, host: '203.0.113.20');
    var selected = first.vm;
    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) => Scaffold(
            body: TextButton(
              onPressed: () => showActivityConsole(context, selected),
              child: const Text('Show console'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Show console'));
    await tester.pumpAndSettle();
    selected = second.vm;
    first.backends.last.output.add('First server package failure');
    second.backends.last.output.add('Second server unrelated activity');
    await tester.pump();
    await tester.pump();
    expect(find.text('203.0.113.10:22'), findsOneWidget);
    expect(find.textContaining('First server package failure'), findsOneWidget);
    expect(
      find.textContaining('Second server unrelated activity'),
      findsNothing,
    );
    await tester.tap(find.text('Close'));
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
  });

  testWidgets('toolbar console can be opened while a server task is busy', (
    tester,
  ) async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connect(h);
    await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
    await tester.pumpAndSettle();
    final gate = Completer<void>();
    h.server.gate = gate;
    final pending = h.vm.refresh();
    await tester.pump();
    expect(h.vm.busy, isTrue);
    await tester.tap(find.byTooltip('Server activity'));
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.byType(ActivityConsole), findsOneWidget);
    h.backends.last.output.add('Installing while console is open.');
    await tester.pump();
    expect(
      find.textContaining('Installing while console is open.'),
      findsOneWidget,
    );
    gate.complete();
    await pending;
    await tester.pump();
    await tester.tap(find.text('Close'));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });
}
