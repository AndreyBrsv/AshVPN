import 'package:ashapp/connection_details.dart';
import 'package:ashapp/credentials_card.dart';
import 'package:ashapp/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('password copy copies only the password and keeps it hidden', (
    tester,
  ) async {
    const details = ConnectionDetails(
      host: '203.0.113.10',
      port: 22,
      user: 'alice',
      password: 'synthetic-copy-placeholder',
    );
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
      const AshappApp(
        home: Scaffold(
          body: CredentialsCard(title: 'SSH access', details: details),
        ),
      ),
    );
    await tester.tap(find.byTooltip('Copy password'));
    await tester.pumpAndSettle();
    expect(copied, details.password);
    expect(find.textContaining(details.password), findsNothing);
    expect(find.text('Password copied. Keep it private.'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('a clipboard failure preserves the masked credentials', (
    tester,
  ) async {
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          throw PlatformException(code: 'clipboard_locked');
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
      const AshappApp(
        home: Scaffold(
          body: CredentialsCard(
            title: 'SSH access',
            details: ConnectionDetails(
              host: '203.0.113.10',
              port: 22,
              user: 'alice',
              password: 'synthetic-copy-placeholder',
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.byTooltip('Copy password'));
    await tester.pumpAndSettle();
    expect(
      find.textContaining('Could not copy to the clipboard'),
      findsOneWidget,
    );
    expect(find.textContaining('synthetic-copy-placeholder'), findsNothing);
    expect(tester.takeException(), isNull);
  });
}
