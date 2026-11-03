import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:ashapp/appearance.dart';
import 'package:ashapp/json_file_store.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class MemoryAppearanceRepository implements AppearanceRepository {
  ThemeMode mode = ThemeMode.system;
  bool failLoad = false;
  bool failSave = false;
  Completer<void>? pendingSave;
  int saves = 0;

  @override
  Future<ThemeMode> load() async {
    if (failLoad) throw const FileSystemException('Synthetic read failure');
    return mode;
  }

  @override
  Future<void> save(ThemeMode value) async {
    saves++;
    await pendingSave?.future;
    if (failSave) throw const FileSystemException('Synthetic write failure');
    mode = value;
  }
}

void main() {
  group('appearance persistence', () {
    late Directory directory;
    late File file;
    late JsonAppearanceRepository repository;

    setUp(() async {
      directory = await Directory.systemTemp.createTemp('ashapp-appearance-');
      file = File('${directory.path}/appearance-settings.json');
      repository = JsonAppearanceRepository(JsonFileStore(file));
    });
    tearDown(() => directory.delete(recursive: true));

    test('new installations follow the system', () async {
      expect(await repository.load(), ThemeMode.system);
    });

    for (final mode in ThemeMode.values) {
      test(
        '${mode.name} survives restart and stores only appearance',
        () async {
          final controller = AppearanceController(repository: repository);
          addTearDown(controller.dispose);
          await controller.select(mode);
          final restarted = AppearanceController(repository: repository);
          addTearDown(restarted.dispose);
          await restarted.initialize();
          expect(restarted.mode, mode);
          expect(jsonDecode(await file.readAsString()), {
            'version': 1,
            'theme': mode.name,
          });
        },
      );
    }

    test('invalid settings fall back safely and can be repaired', () async {
      for (final invalid in [
        'not-json',
        'null',
        '[]',
        '{"version":2,"theme":"dark"}',
        '{"version":1,"theme":"unknown"}',
      ]) {
        await file.writeAsString(invalid);
        final controller = AppearanceController(repository: repository);
        await controller.initialize();
        expect(controller.mode, ThemeMode.system);
        expect(controller.error, isNotNull);
        await controller.select(ThemeMode.dark);
        expect(controller.mode, ThemeMode.dark);
        expect(controller.error, isNull);
        expect(await repository.load(), ThemeMode.dark);
        controller.dispose();
      }
    });
  });

  test('failed writes preserve the previous theme and permit retry', () async {
    final repository = MemoryAppearanceRepository()..mode = ThemeMode.dark;
    final controller = AppearanceController(repository: repository);
    addTearDown(controller.dispose);
    await controller.initialize();
    repository.failSave = true;
    await controller.select(ThemeMode.light);
    expect(controller.mode, ThemeMode.dark);
    expect(repository.mode, ThemeMode.dark);
    expect(controller.error, isNotNull);
    expect(controller.saving, isFalse);
    repository.failSave = false;
    await controller.select(ThemeMode.light);
    expect(controller.mode, ThemeMode.light);
    expect(controller.error, isNull);
  });

  test('overlapping selections cannot reorder writes', () async {
    final repository = MemoryAppearanceRepository()
      ..pendingSave = Completer<void>();
    final controller = AppearanceController(repository: repository);
    addTearDown(controller.dispose);
    await controller.initialize();
    final pending = controller.select(ThemeMode.dark);
    expect(controller.saving, isTrue);
    await controller.select(ThemeMode.light);
    repository.pendingSave!.complete();
    await pending;
    expect(repository.saves, 1);
    expect(controller.mode, ThemeMode.dark);
    expect(repository.mode, ThemeMode.dark);
  });
}
