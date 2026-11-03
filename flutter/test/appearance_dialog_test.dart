import 'package:ashapp/appearance.dart';
import 'package:ashapp/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'appearance_test.dart' show MemoryAppearanceRepository;
import 'support/fakes.dart';

void main() {
  testWidgets(
    'toolbar switches theme live, follows System and keeps the page',
    (tester) async {
      final repository = MemoryAppearanceRepository();
      final appearance = AppearanceController(repository: repository);
      final h = Harness();
      addTearDown(h.vm.dispose);
      addTearDown(appearance.dispose);
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.light;
      addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
      await appearance.initialize();
      await tester.pumpWidget(
        AshappApp(
          appearance: appearance,
          home: HomePage(controller: h.vm),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byIcon(Icons.auto_awesome_mosaic_outlined));
      await tester.pumpAndSettle();
      final homeState = tester.state(find.byType(HomePage));
      await tester.tap(find.byTooltip('Appearance'));
      await tester.pumpAndSettle();

      Brightness brightness() =>
          Theme.of(tester.element(find.text('Appearance').last)).brightness;

      expect(brightness(), Brightness.light);
      await tester.tap(find.text('Dark'));
      await tester.pumpAndSettle();
      expect(brightness(), Brightness.dark);
      expect(repository.mode, ThemeMode.dark);
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.dark;
      await tester.tap(find.text('Light'));
      await tester.pumpAndSettle();
      expect(brightness(), Brightness.light);
      await tester.tap(find.text('System'));
      await tester.pumpAndSettle();
      expect(brightness(), Brightness.dark);
      tester.platformDispatcher.platformBrightnessTestValue = Brightness.light;
      await tester.pumpAndSettle();
      expect(brightness(), Brightness.light);
      await tester.tap(find.text('Done'));
      await tester.pumpAndSettle();
      expect(tester.state(find.byType(HomePage)), same(homeState));
      expect(find.text('Setup templates'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('appearance remains usable in a compact window with large text', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(480, 640);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    tester.platformDispatcher.textScaleFactorTestValue = 1.5;
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final repository = MemoryAppearanceRepository()..failSave = true;
    final appearance = AppearanceController(repository: repository);
    final h = Harness();
    addTearDown(h.vm.dispose);
    addTearDown(appearance.dispose);
    await tester.pumpWidget(
      AshappApp(
        appearance: appearance,
        home: HomePage(controller: h.vm),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Appearance'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Dark'));
    await tester.tap(find.text('Dark'));
    await tester.pumpAndSettle();
    expect(find.textContaining('could not be saved'), findsOneWidget);
    expect(appearance.mode, ThemeMode.system);
    expect(tester.takeException(), isNull);
    repository.failSave = false;
    await tester.ensureVisible(find.text('Dark'));
    await tester.tap(find.text('Dark'));
    await tester.pumpAndSettle();
    expect(appearance.mode, ThemeMode.dark);
    expect(find.textContaining('could not be saved'), findsNothing);
    await tester.tap(find.text('Done'));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });
}
