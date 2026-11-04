import 'dart:io';

import 'package:ashapp/local_data_cleanup.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as path;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory root;
  setUp(() async {
    root = await Directory.systemTemp.createTemp('ashapp-cleanup-');
    root = Directory(await root.resolveSymbolicLinks());
  });
  tearDown(() async => root.delete(recursive: true));

  test(
    'cleanup preserves unrelated entries in a shared vault service',
    () async {
      FlutterSecureStorage.setMockInitialValues({
        'ashapp.ssh.fixture': 'synthetic-placeholder',
        'ashapp.template.fixture': 'synthetic-placeholder',
        'another-app': 'keep',
      });
      await eraseAshappSecrets();
      expect(await const FlutterSecureStorage().readAll(), {
        'another-app': 'keep',
      });
    },
  );

  test(
    'explicit cleanup erases vault first, only removes Ashapp directory',
    () async {
      final data = await Directory(path.join(root.path, 'Ashapp')).create();
      final settings = await File(path.join(data.path, 'servers.json'))
          .writeAsString('{}');
      final unrelated = await File(path.join(root.path, 'other-app'))
          .writeAsString('keep');
      var erased = false;
      await eraseLocalData(
        directory: data,
        eraseSecrets: () async {
          expect(await settings.exists(), isTrue);
          erased = true;
        },
      );
      expect(erased, isTrue);
      expect(await data.exists(), isFalse);
      expect(await unrelated.readAsString(), 'keep');
    },
  );

  test('vault failure keeps settings and aborts uninstall cleanup', () async {
    final data = await Directory(path.join(root.path, 'Ashapp')).create();
    final settings = await File(path.join(data.path, 'templates.json'))
        .writeAsString('{}');
    await expectLater(
      eraseLocalData(
        directory: data,
        eraseSecrets: () async {
          throw StateError('synthetic locked vault');
        },
      ),
      throwsStateError,
    );
    expect(await settings.exists(), isTrue);
  });

  test('unexpected directory never touches the vault or files', () async {
    final data = await Directory(path.join(root.path, 'Other')).create();
    var erased = false;
    await expectLater(
      eraseLocalData(
        directory: data,
        eraseSecrets: () async {
          erased = true;
        },
      ),
      throwsA(isA<FileSystemException>()),
    );
    expect(erased, isFalse);
    expect(await data.exists(), isTrue);
  });

  test('missing settings still clears orphaned Ashapp vault entries', () async {
    var erased = false;
    await eraseLocalData(
      directory: Directory(path.join(root.path, 'Ashapp')),
      eraseSecrets: () async {
        erased = true;
      },
    );
    expect(erased, isTrue);
  });
}
