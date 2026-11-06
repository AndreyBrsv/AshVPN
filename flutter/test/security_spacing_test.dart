import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/private_key_field.dart';
import 'package:ashapp/security_panel.dart';
import 'package:ashapp/ui_components.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

void main() {
  for (final scale in [1.0, 1.5]) {
    testWidgets('SSH key controls remain separated at 420px and text $scale', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(420, 600);
      tester.view.devicePixelRatio = 1;
      tester.platformDispatcher.textScaleFactorTestValue = scale;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
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
      await tester.pumpWidget(
        AshappApp(
          home: Scaffold(
            body: SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: SecurityPanel(controller: h.vm),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final description = find.text(
        'A generated key is unique to this server. Imported keys and passphrases stay in the OS vault.',
      );
      final generate = find.widgetWithText(
        OutlinedButton,
        'Generate and install SSH key',
      );
      final key = find.byType(PrivateKeyField);
      final passphrase = find.byType(SecretField);
      final install = find.widgetWithText(
        OutlinedButton,
        'Import and verify SSH key',
      );

      expect(
        tester.getRect(generate).top - tester.getRect(description).bottom,
        greaterThanOrEqualTo(12),
      );
      expect(
        tester.getRect(key).top - tester.getRect(generate).bottom,
        greaterThanOrEqualTo(16),
      );
      expect(
        tester.getRect(passphrase).top - tester.getRect(key).bottom,
        greaterThanOrEqualTo(12),
      );
      expect(
        tester.getRect(install).top - tester.getRect(passphrase).bottom,
        greaterThanOrEqualTo(12),
      );

      final pasteBounds = tester.getRect(
        find.byTooltip('Paste SSH private key'),
      );
      final clearBounds = tester.getRect(
        find.byTooltip('Clear SSH private key'),
      );
      final fieldBounds = tester.getRect(key);
      expect(pasteBounds.left, greaterThanOrEqualTo(fieldBounds.left));
      expect(clearBounds.right, lessThanOrEqualTo(fieldBounds.right));
      expect(clearBounds.left, greaterThanOrEqualTo(pasteBounds.right));
      expect(pasteBounds.width, greaterThanOrEqualTo(48));
      expect(clearBounds.width, greaterThanOrEqualTo(48));
      expect(
        tester
            .renderObject<RenderParagraph>(
              find.text('Import SSH private key (paste)'),
            )
            .didExceedMaxLines,
        isFalse,
        reason:
            'Label ${tester.getSize(find.text('Import SSH private key (paste)'))}; field ${fieldBounds.size}',
      );
      expect(
        tester
            .renderObject<RenderParagraph>(
              find.text('Use Paste to preserve the original key format.'),
            )
            .didExceedMaxLines,
        isFalse,
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }
}
