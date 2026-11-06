import 'dart:convert';
import 'dart:io';

import 'package:ashapp/host_key_store.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory directory;
  late File file;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('ashapp_hosts_');
    file = File('${directory.path}/known_hosts.json');
  });
  tearDown(() => directory.delete(recursive: true));

  test('changed host key is rejected without offering to trust it', () async {
    final store = KnownHosts(file);
    expect(
      await store.verify(
        '203.0.113.1:22',
        'ssh-ed25519',
        'SHA256:test-a',
        (_, _) async => true,
      ),
      isTrue,
    );
    expect(
      await store.verify(
        '203.0.113.1:22',
        'ssh-ed25519',
        'SHA256:test-b',
        (_, _) async => fail('A changed key must not be offered for approval.'),
      ),
      isFalse,
    );
    expect(
      (jsonDecode(await file.readAsString()) as Map).values.single,
      'ssh-ed25519 SHA256:test-a',
    );
  });

  test(
    'simultaneous connections merge trusted keys rather than overwriting them',
    () async {
      final accepted = await Future.wait([
        for (final index in [1, 2])
          KnownHosts(file).verify(
            '203.0.113.$index:22',
            'ssh-ed25519',
            'SHA256:test-$index',
            (_, _) async => true,
          ),
      ]);
      expect(accepted, everyElement(isTrue));
      expect((jsonDecode(await file.readAsString()) as Map).length, 2);
    },
  );

  test('declined key is never persisted', () async {
    expect(
      await KnownHosts(file).verify(
        '203.0.113.1:22',
        'ssh-ed25519',
        'SHA256:test',
        (_, _) async => false,
      ),
      isFalse,
    );
    expect(await file.exists(), isFalse);
  });

  test(
    'forget removes only the selected endpoint and requires trust again',
    () async {
      final store = KnownHosts(file);
      for (final endpoint in ['203.0.113.1:22', '203.0.113.2:22']) {
        await store.verify(
          endpoint,
          'ssh-ed25519',
          'SHA256:test',
          (_, _) async => true,
        );
      }
      await store.forget('203.0.113.1:22');
      expect((jsonDecode(await file.readAsString()) as Map).keys, [
        '203.0.113.2:22',
      ]);
      var asked = false;
      expect(
        await store.verify('203.0.113.1:22', 'ssh-ed25519', 'SHA256:new', (
          _,
          _,
        ) async {
          asked = true;
          return true;
        }),
        isTrue,
      );
      expect(asked, isTrue);
    },
  );

  test('malformed key store fails closed and is preserved', () async {
    await file.writeAsString('null');
    await expectLater(
      KnownHosts(file).verify(
        '203.0.113.1:22',
        'ssh-ed25519',
        'SHA256:test',
        (_, _) async => fail('Corrupt stores must not be reset.'),
      ),
      throwsFormatException,
    );
    expect(await file.readAsString(), 'null');
  });
}
