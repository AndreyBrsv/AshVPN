import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:ashapp/app_update.dart';
import 'package:ashapp/json_file_store.dart';
import 'package:ashapp/server_workspace.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as path;

import 'support/fakes.dart';

class FixtureTransport implements UpdateTransport {
  final bodies = <String, List<int>>{};
  final requests = <Uri>[];
  Future<Stream<List<int>>> Function(Uri, UpdateCancellation)? intercept;
  @override
  Future<Stream<List<int>>> get(Uri uri, UpdateCancellation token) async {
    requests.add(uri);
    if (intercept != null) return intercept!(uri, token);
    final value = bodies[uri.toString()];
    if (value == null) throw const SocketException('synthetic offline');
    return Stream.value(value);
  }
}

class FixtureRuntime implements UpdateRuntime {
  int opened = 0, quits = 0;
  String? receivedDigest;
  bool failOpen = false, failQuit = false;
  @override
  Future<UpdatePlatform> platform() async => UpdatePlatform(
    version: AppVersion.parse('0.0.3+3'),
    target: 'windows-x64',
  );
  @override
  Future<void> openInstaller(
    File file, {
    required String expectedSha256,
  }) async {
    receivedDigest = expectedSha256;
    if (failOpen) throw StateError('synthetic launch failure');
    opened++;
  }

  @override
  Future<void> quit() async {
    quits++;
    if (failQuit) throw StateError('synthetic quit failure');
  }
}

Map<String, dynamic> releaseFixture(
  FixtureTransport transport, {
  String version = '0.0.4',
}) {
  final assets = <Map<String, dynamic>>[];
  final hashes = <String, String>{};
  Map<String, dynamic> asset(String name, List<int> bytes) {
    final digest = sha256.convert(bytes).toString();
    final url =
        'https://github.com/AndreyBrsv/Ashapp/releases/download/v$version/$name';
    hashes[name] = digest;
    transport.bodies[url] = bytes;
    return {
      'name': name,
      'state': 'uploaded',
      'browser_download_url': url,
      'size': bytes.length,
      'digest': 'sha256:$digest',
    };
  }

  for (final target in UpdatePlatform.targets) {
    final stem = 'Ashapp-v$version-$target';
    final installer = asset(
      '$stem-setup${target == 'windows-x64' ? '.exe' : '.pkg'}',
      utf8.encode('synthetic non-executable $target installer'),
    );
    assets.add(installer);
    assets.add(
      asset(
        '$stem.build.json',
        utf8.encode(
          jsonEncode({
            'version': version,
            'source_commit': 'a' * 40,
            'target': target,
            'installer': installer['name'],
            'installer_sha256': (installer['digest'] as String).substring(7),
            'installer_size': installer['size'],
          }),
        ),
      ),
    );
  }
  assets.add(
    asset(
      'SHA256SUMS',
      utf8.encode(
        hashes.entries.map((item) => '${item.value}  ${item.key}\n').join(),
      ),
    ),
  );
  final release = <String, dynamic>{
    'tag_name': 'v$version',
    'draft': false,
    'prerelease': false,
    'assets': assets,
    'body': 'Synthetic release notes.',
  };
  transport
          .bodies['https://api.github.com/repos/AndreyBrsv/Ashapp/releases/latest'] =
      utf8.encode(jsonEncode(release));
  return release;
}

void main() {
  late Directory root;
  late FixtureTransport transport;
  late UpdateRepository repository;
  late FixtureRuntime runtime;
  late AppUpdateController vm;
  final current = UpdatePlatform(
    version: AppVersion.parse('0.0.3'),
    target: 'windows-x64',
  );
  setUp(() async {
    root = await Directory.systemTemp.createTemp('ashapp-update-test-');
    transport = FixtureTransport();
    releaseFixture(transport);
    repository = UpdateRepository(
      transport: transport,
      cache: Directory(path.join(root.path, 'updates')),
    );
    runtime = FixtureRuntime();
    vm = AppUpdateController(
      repository: repository,
      runtime: runtime,
      preferences: JsonFileStore(
        File(path.join(root.path, 'update-settings.json')),
      ),
    );
  });
  tearDown(() async {
    vm.dispose();
    await root.delete(recursive: true);
  });

  test('compares numeric stable versions and ignores build metadata', () {
    expect(
      AppVersion.parse('1.10.0').compareTo(AppVersion.parse('1.9.99')),
      greaterThan(0),
    );
    expect(AppVersion.parse('0.0.3+3').compareTo(AppVersion.parse('0.0.3')), 0);
    for (final invalid in [
      'v0.0.4',
      '01.0.0',
      '1.0.0-beta',
      '1.0',
      '1.0.0/evil',
    ]) {
      expect(() => AppVersion.parse(invalid), throwsA(isA<UpdateException>()));
    }
  });

  test('does not downgrade or update the same version', () {
    expect(
      AppRelease.newer(releaseFixture(transport, version: '0.0.3'), current),
      isNull,
    );
    expect(
      AppRelease.newer(releaseFixture(transport, version: '0.0.2'), current),
      isNull,
    );
  });

  test('selects the actual process platform, including Apple Silicon', () {
    final raw = releaseFixture(transport);
    for (final target in UpdatePlatform.targets) {
      final platform = UpdatePlatform.fromJson({
        'version': '0.0.3',
        'target': target,
      });
      final release = AppRelease.newer(raw, platform)!;
      expect(release.installer.name, contains(target));
      expect(
        path.extension(release.installer.name),
        target == 'windows-x64' ? '.exe' : '.pkg',
      );
    }
    expect(
      () => UpdatePlatform.fromJson({
        'version': '0.0.3',
        'target': 'windows-arm64',
      }),
      throwsA(isA<UpdateException>()),
    );
  });

  test(
    'rejects drafts, prereleases, duplicate files and partial platform uploads',
    () {
      for (final field in ['draft', 'prerelease']) {
        final raw = releaseFixture(transport)..[field] = true;
        expect(
          () => AppRelease.newer(raw, current),
          throwsA(isA<UpdateException>()),
        );
      }
      var raw = releaseFixture(transport);
      (raw['assets'] as List).add((raw['assets'] as List).first);
      expect(
        () => AppRelease.newer(raw, current),
        throwsA(isA<UpdateException>()),
      );
      raw = releaseFixture(transport);
      (raw['assets'] as List).removeAt(
        2,
      ); // Another OS is missing; Windows must wait.
      expect(
        () => AppRelease.newer(raw, current),
        throwsA(isA<UpdateException>()),
      );
    },
  );

  test('refuses unexpected URLs, missing hashes and oversized installers', () {
    for (final entry in [
      MapEntry('browser_download_url', 'https://attacker.invalid/payload.exe'),
      MapEntry('digest', null),
      MapEntry('size', 2 * 1024 * 1024 * 1024),
    ]) {
      final raw = releaseFixture(transport);
      (raw['assets'] as List).first[entry.key] = entry.value;
      expect(
        () => AppRelease.newer(raw, current),
        throwsA(isA<UpdateException>()),
      );
    }
    for (final url in [
      'http://github.com/a',
      'https://github.com.evil.invalid/a',
      'https://user@github.com/a',
      'https://github.com:444/a',
      'https://localhost/a',
    ]) {
      expect(GitHubUpdateTransport.allowed(Uri.parse(url)), isFalse);
    }
    expect(
      GitHubUpdateTransport.allowed(
        Uri.parse('https://release-assets.githubusercontent.com/asset'),
      ),
      isTrue,
    );
  });

  test('downloads exact bytes after verifying metadata and rechecks before handoff', () async {
    final release = (await repository.check(current))!;
    final values = <double>[];
    final prepared = await repository.download(
      release,
      current,
      UpdateCancellation(),
      values.add,
    );
    expect(
      await prepared.file.readAsBytes(),
      transport.bodies[release.installer.url.toString()],
    );
    expect(values.last, 1);
    await repository.verify(prepared);
    await prepared.file.writeAsString('changed after download');
    await expectLater(
      repository.verify(prepared),
      throwsA(isA<UpdateException>()),
    );
  });

  test('tampered metadata never downloads or stages an installer', () async {
    final release = (await repository.check(current))!;
    transport.bodies[release.manifest.url.toString()] = utf8.encode('tampered');
    await expectLater(
      repository.download(release, current, UpdateCancellation(), (_) {}),
      throwsA(isA<UpdateException>()),
    );
    expect(transport.requests, isNot(contains(release.installer.url)));
    expect(await repository.cache.exists(), isFalse);
  });

  test(
    'corrupt, truncated and oversized installers leave no ready file',
    () async {
      final release = (await repository.check(current))!;
      for (final bytes in [
        List.filled(release.installer.size, 0),
        [1],
        List.filled(release.installer.size + 1, 0),
      ]) {
        transport.bodies[release.installer.url.toString()] = bytes;
        await expectLater(
          repository.download(release, current, UpdateCancellation(), (_) {}),
          throwsA(isA<UpdateException>()),
        );
        expect(await repository.cache.list().toList(), isEmpty);
      }
    },
  );

  test('cancelling between chunks discards a partial installer', () async {
    final release = (await repository.check(current))!;
    final original = Map.of(transport.bodies);
    final token = UpdateCancellation();
    transport.intercept = (uri, _) async {
      if (uri != release.installer.url) {
        return Stream.value(original[uri.toString()]!);
      }
      return Stream<List<int>>.multi((sink) {
        sink.add([1, 2]);
        token.cancel();
        sink.add([3]);
        sink.close();
      });
    };
    await expectLater(
      repository.download(release, current, token, (_) {}),
      throwsA(isA<UpdateException>()),
    );
    expect(await repository.cache.list().toList(), isEmpty);
  });

  test('automatic checks are daily, opt-out persists and requests contain no server data', () async {
    await vm.start();
    expect(vm.release!.version.toString(), '0.0.4');
    expect(runtime.opened, 0);
    expect(
      transport.requests.single.toString(),
      'https://api.github.com/repos/AndreyBrsv/Ashapp/releases/latest',
    );
    await vm.setAutomatic(false);
    final raw = jsonDecode(
      await File(path.join(root.path, 'update-settings.json')).readAsString(),
    ) as Map;
    expect(raw.keys.toSet(), {'version', 'automatic', 'last_checked'});
    vm.dispose();
    vm = AppUpdateController(
      repository: repository,
      runtime: runtime,
      preferences: JsonFileStore(
        File(path.join(root.path, 'update-settings.json')),
      ),
    );
    await vm.start();
    expect(vm.automatic, isFalse);
    expect(transport.requests.length, 1);
    await vm.check();
    expect(transport.requests.length, 2);
  });

  test(
    'recent check and corrupt preferences do not trigger background traffic',
    () async {
      await vm.preferences.write({
        'version': 1,
        'automatic': true,
        'last_checked': DateTime.now().toUtc().toIso8601String(),
      });
      await vm.start();
      expect(transport.requests, isEmpty);
      vm.dispose();
      await File(path.join(root.path, 'update-settings.json'))
          .writeAsString('broken');
      vm = AppUpdateController(
        repository: repository,
        runtime: runtime,
        preferences: JsonFileStore(
          File(path.join(root.path, 'update-settings.json')),
        ),
      );
      await vm.start();
      expect(vm.automatic, isFalse);
      expect(transport.requests, isEmpty);
      await vm.check();
      expect(vm.release, isNotNull);
    },
  );

  test('installation is blocked while any server is busy and checked again after verification', () async {
    await vm.check();
    await vm.download();
    expect(await vm.install(canInstall: () => false), isFalse);
    expect(runtime.opened, 0);
    var calls = 0;
    expect(await vm.install(canInstall: () => ++calls == 1), isFalse);
    expect(runtime.opened, 0);
    expect(vm.locksWorkspace, isFalse);
    expect(await vm.install(canInstall: () => true), isTrue);
    expect(runtime.opened, 1);
    expect(runtime.quits, 1);
    expect(runtime.receivedDigest, vm.release!.installer.sha256);
    expect(vm.phase, UpdatePhase.handedOff);
  });

  test('launch failure keeps the app running; failed quit cannot relaunch installer', () async {
    await vm.check();
    await vm.download();
    runtime.failOpen = true;
    expect(await vm.install(canInstall: () => true), isFalse);
    expect(runtime.quits, 0);
    expect(vm.phase, UpdatePhase.ready);
    runtime.failOpen = false;
    runtime.failQuit = true;
    expect(await vm.install(canInstall: () => true), isFalse);
    expect(vm.phase, UpdatePhase.handedOff);
    expect(await vm.install(canInstall: () => true), isFalse);
    expect(runtime.opened, 1);
  });

  test('workspace update gate blocks operations on existing and newly added servers', () async {
    final harness = Harness();
    final workspace = ServerWorkspace(harness.vm);
    addTearDown(() {
      workspace.dispose();
      workspace.closeSessions();
    });
    final second = workspace.create();
    workspace.operationsSuspended = true;
    expect(await harness.vm.refresh(), isFalse);
    expect(await second.refresh(), isFalse);
    final third = workspace.create();
    expect(await third.refresh(), isFalse);
    expect(third.error, contains('operations are paused'));
    workspace.operationsSuspended = false;
    await third.initialize();
    expect(third.error, isEmpty);
  });

  test(
    'offline checks are recoverable and expose no raw transport error',
    () async {
      transport.bodies.clear();
      await vm.check();
      expect(vm.error, contains('Could not check'));
      expect(vm.error, isNot(contains('synthetic')));
      releaseFixture(transport);
      await vm.check();
      expect(vm.error, isEmpty);
      expect(vm.release, isNotNull);
    },
  );

  test('a changed prepared file can be removed and downloaded again', () async {
    await vm.check();
    await vm.download();
    final original = vm.prepared!.directory;
    await vm.prepared!.file.writeAsString('synthetic changed bytes');
    expect(await vm.install(canInstall: () => true), isFalse);
    expect(runtime.opened, 0);
    await vm.discardDownload();
    expect(await original.exists(), isFalse);
    expect(vm.prepared, isNull);
    await vm.download();
    expect(vm.phase, UpdatePhase.ready);
  });
}
