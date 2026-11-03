import 'dart:io';

import 'package:ashapp/app_update.dart';
import 'package:ashapp/app_update_dialog.dart';
import 'package:ashapp/json_file_store.dart';
import 'package:ashapp/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as path;

import 'app_update_test.dart'
    show FixtureRuntime, FixtureTransport, releaseFixture;
import 'support/fakes.dart';

// Filesystem/integrity behavior is covered by app_update_test. Widget tests
// keep asynchronous disk IO outside Flutter's fake event-loop zone.
class MemoryUpdateRepository extends UpdateRepository {
  MemoryUpdateRepository({required super.transport, required super.cache});
  @override
  Future<PreparedUpdate> download(
    AppRelease release,
    UpdatePlatform platform,
    UpdateCancellation token,
    void Function(double) progress,
  ) async {
    progress(1);
    return PreparedUpdate(
      release,
      File(path.join(cache.path, release.installer.name)),
      cache,
    );
  }

  @override
  Future<void> verify(PreparedUpdate update) async {}
}

class MemoryUpdatePreferences extends JsonFileStore {
  MemoryUpdatePreferences(super.file);
  Object? value;
  @override
  Future<Object?> read() async => value;
  @override
  Future<void> write(Object? value) async {
    this.value = value;
  }
}

void main() {
  late Directory root;
  late AppUpdateController vm;
  late FixtureRuntime runtime;
  late ChangeNotifier workspace;
  setUp(() async {
    root = await Directory.systemTemp.createTemp('ashapp-update-ui-');
    final transport = FixtureTransport();
    releaseFixture(transport);
    runtime = FixtureRuntime();
    workspace = ChangeNotifier();
    vm = AppUpdateController(
      repository: MemoryUpdateRepository(
        transport: transport,
        cache: Directory(path.join(root.path, 'updates')),
      ),
      runtime: runtime,
      preferences: MemoryUpdatePreferences(
        File(path.join(root.path, 'update-settings.json')),
      ),
    );
  });
  tearDown(() async {
    vm.dispose();
    workspace.dispose();
    await root.delete(recursive: true);
  });

  testWidgets(
    'the home toolbar exposes app updates without a server connection',
    (tester) async {
      final harness = Harness();
      addTearDown(harness.vm.dispose);
      await tester.runAsync(vm.start);
      await tester.pumpWidget(
        AshappApp(
          home: HomePage(controller: harness.vm, updates: vm),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.byTooltip('Update available'), findsOneWidget);
      final repository = vm.repository.transport as FixtureTransport;
      final checksBefore = repository.requests.length;
      await tester.tap(find.byTooltip('Update available'));
      await tester.pumpAndSettle();
      expect(repository.requests.length, checksBefore + 1);
      expect(find.text('App updates'), findsOneWidget);
      expect(find.text('Check automatically'), findsOneWidget);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets(
    'download, all-server task guard, confirmation cancellation and handoff',
    (tester) async {
      tester.view.physicalSize = const Size(1000, 1100);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await tester.runAsync(vm.check);
      var otherServerBusy = true;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: AppUpdateDialog(
              controller: vm,
              workspace: workspace,
              canInstall: () => !otherServerBusy,
            ),
          ),
        ),
      );
      await tester.tap(find.text('Download update'));
      await tester.pumpAndSettle();
      expect(vm.phase, UpdatePhase.ready);
      FilledButton installButton() => tester.widget<FilledButton>(
        find.widgetWithText(FilledButton, 'Install update…'),
      );
      expect(installButton().onPressed, isNull);
      expect(
        find.textContaining('Finish tasks on all servers'),
        findsOneWidget,
      );
      otherServerBusy = false;
      workspace.notifyListeners();
      await tester.pumpAndSettle();
      expect(installButton().onPressed, isNotNull);
      await tester.tap(find.text('Install update…'));
      await tester.pumpAndSettle();
      expect(
        find.textContaining('disconnect all SSH sessions'),
        findsOneWidget,
      );
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      expect(runtime.opened, 0);
      expect(vm.phase, UpdatePhase.ready);
      await tester.tap(find.text('Install update…'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Open installer'));
      await tester.pumpAndSettle();
      expect(runtime.opened, 1);
      expect(runtime.quits, 1);
      expect(vm.phase, UpdatePhase.handedOff);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets(
    'update controls scroll without overflow in a narrow window at large text size',
    (tester) async {
      tester.view.physicalSize = const Size(420, 650);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await tester.runAsync(vm.check);
      await tester.pumpWidget(
        MaterialApp(
          home: MediaQuery(
            data: const MediaQueryData(textScaler: TextScaler.linear(1.5)),
            child: Scaffold(
              body: AppUpdateDialog(
                controller: vm,
                workspace: workspace,
                canInstall: () => true,
              ),
            ),
          ),
        ),
      );
      expect(tester.takeException(), isNull);
      expect(find.byType(SingleChildScrollView), findsOneWidget);
    },
  );
}
