import 'package:ashapp/connection_details.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

const _login = ConnectionDetails(
  host: '203.0.113.10',
  port: 22,
  user: 'root',
  password: 'synthetic-login-placeholder',
);

ServerTemplate _answers({String deployment = 'amnezia'}) => ServerTemplate(
  name: 'Shared test',
  blockPing: false,
  disableRoot: false,
  installAwg: true,
  installSocks: false,
  awgPort: 585,
  clientNames: ['Phone', 'Laptop'],
  createAdmin: false,
  awgDeployment: deployment,
  protectSsh: false,
  configureFirewall: false,
);

void _sharedState(Harness h) => h.server.state.addAll({
  'awg': true,
  'kernel': true,
  'awg_configured': true,
  'awg_host_configured': false,
  'awg_deployment': 'amnezia',
  'awg_shared_guard': true,
  'awg_port': 585,
  'external_awg': [
    {'source': 'amnezia-awg2', 'running': true},
  ],
});

void main() {
  test(
    'shared setup uses one explicit container source for every device',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(_login, (_, _) async => true);
      expect(await h.vm.provision(_answers(), const SetupSecrets()), isTrue);
      expect(
        h.server.calls.where((c) => c.$1 == 'install-awg-amnezia').single.$2,
        [_login.host, '585', '1.1.1.1'],
      );
      expect(
        h.server.calls.any((c) => c.$1 == 'install-awg-configured'),
        isFalse,
      );
      expect(
        h.server.calls.where((c) => c.$1 == 'add-client').map((c) => c.$2),
        [
          ['Phone', 'amnezia-awg2', _login.host, '1.1.1.1'],
          ['Laptop', 'amnezia-awg2', _login.host, '1.1.1.1'],
        ],
      );
      expect(h.vm.clientSources, ['amnezia-awg2']);
      expect(h.vm.setupComplete, isTrue);
    },
  );

  test(
    'repeated shared setup preserves installation and scopes existing names',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      _sharedState(h);
      h.server.clientRows = [
        {'name': 'Phone', 'source': 'amnezia-awg2'},
        {'name': 'Laptop', 'source': 'amnezia-awg'},
      ];
      await h.vm.connect(_login, (_, _) async => true);
      expect(await h.vm.provision(_answers(), const SetupSecrets()), isTrue);
      expect(
        h.server.calls.any((c) => c.$1.startsWith('install-awg')),
        isFalse,
      );
      expect(h.server.calls.where((c) => c.$1 == 'add-client').single.$2, [
        'Laptop',
        'amnezia-awg2',
        _login.host,
        '1.1.1.1',
      ]);
    },
  );

  for (final host in [true, false]) {
    test(
      'shared setup refuses ${host ? 'host' : 'unowned container'} adoption',
      () async {
        final h = Harness();
        addTearDown(h.vm.dispose);
        h.server.state.addAll({
          'awg_configured': true,
          'awg_host_configured': host,
          if (!host)
            'external_awg': [
              {'source': 'amnezia-awg2', 'running': true},
            ],
        });
        await h.vm.connect(_login, (_, _) async => true);
        expect(await h.vm.provision(_answers(), const SetupSecrets()), isFalse);
        expect(h.vm.error, contains('will not replace or migrate'));
        expect(
          h.server.calls.any((c) => c.$1.startsWith('install-awg')),
          isFalse,
        );
        expect(h.server.calls.any((c) => c.$1 == 'add-client'), isFalse);
      },
    );
  }

  test('host setup cannot replace a shared deployment', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    _sharedState(h);
    await h.vm.connect(_login, (_, _) async => true);
    expect(
      await h.vm.provision(_answers(deployment: 'host'), const SetupSecrets()),
      isFalse,
    );
    expect(h.server.calls.any((c) => c.$1.startsWith('install-awg')), isFalse);
  });

  test(
    'repeated shared setup preserves case-insensitive names from Amnezia',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      _sharedState(h);
      h.server.clientRows = [
        {'name': 'phone', 'name_key': 'phone', 'source': 'amnezia-awg2'},
      ];
      await h.vm.connect(_login, (_, _) async => true);
      expect(await h.vm.provision(_answers(), const SetupSecrets()), isTrue);
      expect(
        h.server.calls.where((c) => c.$1 == 'add-client').single.$2.first,
        'Laptop',
      );
    },
  );

  test('a broken shared kernel guard disables creating more access', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    _sharedState(h);
    h.server.state['awg_shared_guard'] = false;
    await h.vm.connect(_login, (_, _) async => true);
    expect(h.vm.clientSources, isEmpty);
    expect(await h.vm.addClient('Phone', source: 'amnezia-awg2'), isFalse);
    expect(h.server.calls.any((c) => c.$1 == 'add-client'), isFalse);
  });

  test(
    'unknown verification or userspace mode cannot create shared access',
    () async {
      for (final drift in [
        <String, Object>{'awg_error': 'Process inspection failed.'},
        <String, Object>{'userspace': true},
      ]) {
        final h = Harness();
        addTearDown(h.vm.dispose);
        _sharedState(h);
        h.server.state.addAll(drift);
        await h.vm.connect(_login, (_, _) async => true);
        expect(h.vm.clientSources, isEmpty);
        expect(await h.vm.addClient('Phone', source: 'amnezia-awg2'), isFalse);
        expect(h.server.calls.any((c) => c.$1 == 'add-client'), isFalse);
      }
    },
  );

  test(
    'shared setup refuses unsupported VPS architecture before VPN changes',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.state['architecture'] = 'aarch64';
      await h.vm.connect(_login, (_, _) async => true);
      expect(await h.vm.provision(_answers(), const SetupSecrets()), isFalse);
      expect(h.vm.error, contains('x86_64 VPS'));
      expect(
        h.server.calls.any((c) => c.$1.startsWith('install-awg')),
        isFalse,
      );
    },
  );
}
