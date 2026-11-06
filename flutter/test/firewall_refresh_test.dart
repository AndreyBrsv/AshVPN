import 'dart:convert';

import 'package:ashapp/connection_details.dart';
import 'package:ashapp/security_panel.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

Future<void> connect(Harness harness, String address) => harness.vm
    .connect(
      ConnectionDetails(
        host: address,
        port: 22,
        user: 'alice',
        password: 'synthetic-refresh-placeholder',
      ),
      (_, _) async => true,
    )
    .then((connected) => expect(connected, isTrue));

Future<void> render(WidgetTester tester, Harness harness) => tester.pumpWidget(
  MaterialApp(
    home: Scaffold(
      body: SingleChildScrollView(
        child: ListenableBuilder(
          listenable: harness.vm,
          builder: (_, _) => SecurityPanel(controller: harness.vm),
        ),
      ),
    ),
  ),
);

void main() {
  testWidgets('refresh reviews existing protection without toggling it off', (
    tester,
  ) async {
    final active = Harness(), other = Harness();
    addTearDown(active.vm.dispose);
    addTearDown(other.vm.dispose);
    active.server.security['firewall'] = {'managed': true, 'enabled': true};
    await connect(active, '203.0.113.10');
    await connect(other, '203.0.113.20');
    active.server.calls.clear();
    other.server.calls.clear();
    await render(tester, active);

    await tester.ensureVisible(find.text('Refresh firewall ports'));
    await tester.tap(find.text('Refresh firewall ports'));
    await tester.pumpAndSettle();
    expect(find.text('Refresh firewall ports?'), findsOneWidget);
    expect(find.textContaining('Preserved TCP ports: [22]'), findsOneWidget);
    expect(
      active.server.calls.where((call) => call.$1 == 'security-stage'),
      isEmpty,
    );
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(active.server.pendingSecurity, isNull);

    await tester.tap(find.text('Refresh firewall ports'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();
    final staged = active.server.calls.singleWhere(
      (call) => call.$1 == 'security-stage',
    );
    expect(jsonDecode(staged.$2.first), {'firewall': true});
    expect(
      active.server.calls.where((call) => call.$1 == 'security-confirm'),
      hasLength(1),
    );
    expect(active.vm.security!['firewall']['enabled'], isTrue);
    expect(other.server.calls, isEmpty);
    expect(active.vm.error, isEmpty);
    expect(tester.takeException(), isNull);
  });

  testWidgets('refresh cannot discard pending security choices', (
    tester,
  ) async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.server.security['firewall'] = {'managed': true, 'enabled': true};
    await connect(h, '203.0.113.10');
    await render(tester, h);
    await tester.ensureVisible(find.text('Firewall protection'));
    await tester.tap(find.text('Firewall protection'));
    await tester.pumpAndSettle();
    final refresh = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Refresh firewall ports'),
    );
    expect(refresh.onPressed, isNull);
    expect(
      find.text('Apply pending security choices before refreshing ports.'),
      findsOneWidget,
    );
    final firewall = tester.widget<CheckboxListTile>(
      find.ancestor(
        of: find.text('Firewall protection'),
        matching: find.byType(CheckboxListTile),
      ),
    );
    expect(firewall.value, isFalse);
    expect(h.server.pendingSecurity, isNull);
    expect(tester.takeException(), isNull);
  });

  testWidgets('unmanaged firewall has no refresh shortcut', (tester) async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connect(h, '203.0.113.10');
    await render(tester, h);
    expect(find.text('Refresh firewall ports'), findsNothing);
  });

  testWidgets('drifted protection can be explicitly disabled', (tester) async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.server.security['firewall'] = {
      'managed': true,
      'enabled': false,
      'error': 'Synthetic firewall drift.',
    };
    await connect(h, '203.0.113.10');
    h.server.calls.clear();
    await render(tester, h);
    final tile = find.ancestor(
      of: find.text('Firewall protection'),
      matching: find.byType(CheckboxListTile),
    );
    expect(tester.widget<CheckboxListTile>(tile).value, isTrue);
    expect(
      find.textContaining('Effective firewall protection: Needs review'),
      findsOneWidget,
    );
    expect(find.text('Synthetic firewall drift.'), findsOneWidget);
    await tester.ensureVisible(find.text('Firewall protection'));
    await tester.tap(find.text('Firewall protection'));
    await tester.pumpAndSettle();
    expect(tester.widget<CheckboxListTile>(tile).value, isFalse);
    await tester.ensureVisible(find.text('Review and apply changes'));
    await tester.tap(find.text('Review and apply changes'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();
    final staged = h.server.calls.singleWhere(
      (call) => call.$1 == 'security-stage',
    );
    expect(jsonDecode(staged.$2.first), {'firewall': false});
    expect(tester.widget<CheckboxListTile>(tile).value, isFalse);
    expect(find.text('Refresh firewall ports'), findsNothing);
    expect(h.vm.error, isEmpty);
    expect(tester.takeException(), isNull);
  });
}
