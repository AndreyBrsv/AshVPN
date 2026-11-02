import 'dart:async';

import 'package:ashapp/connection_details.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:ashapp/workspace_controller.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

const login = ConnectionDetails(
  host: '203.0.113.10',
  port: 22,
  user: 'root',
  password: 'test-session-placeholder',
);
ServerTemplate answers({
  bool awg = true,
  bool socks = true,
  bool admin = true,
  bool disableRoot = true,
  bool rotate = true,
  bool ping = true,
  List<String> clients = const ['phone', 'laptop'],
}) => ServerTemplate(
  name: 'Friends',
  blockPing: ping,
  disableRoot: disableRoot,
  installAwg: awg,
  installSocks: socks,
  awgPort: 585,
  clientNames: clients,
  createAdmin: admin,
  changeRootPassword: rotate,
);
const protectedAnswers = SetupSecrets(
  rootPassword: 'test-root-placeholder',
  adminName: 'alice',
  adminPassword: 'test-admin-placeholder',
  socksUser: 'proxy',
  socksPassword: 'test_proxy_placeholder',
);

Future<void> connect(Harness h) async {
  expect(await h.vm.connect(login, (_, _) async => true), isTrue);
}

void main() {
  test(
    'forgetting SSH credentials removes saved root and administrator passwords',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      await h.vm.provision(answers(), protectedAnswers);
      expect(await h.vm.forgetPassword(), isTrue);
      expect(await h.vm.vault.account(login.host, login.port, 'root'), isNull);
      expect(await h.vm.vault.account(login.host, login.port, 'alice'), isNull);
      expect(h.vm.connected, isTrue);
    },
  );
  test(
    'unexpected SSH closure invalidates clients and live service state',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      await h.vm.provision(answers(), protectedAnswers);
      await h.backends.firstWhere((b) => !b.closed).connection.close();
      await Future<void>.delayed(Duration.zero);
      expect(h.vm.connected, isFalse);
      expect(h.vm.clients, isEmpty);
      expect(h.vm.socks, isNull);
      expect(h.vm.server, isEmpty);
      expect(h.vm.message, contains('Reconnect'));
    },
  );
  test(
    'one setup path applies every answer and verifies the final server',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      expect(await h.vm.provision(answers(), protectedAnswers), isTrue);
      expect(h.vm.setupComplete, isTrue);
      expect(h.vm.tasks.every((task) => task.state == TaskState.done), isTrue);
      expect(h.vm.ssh!.user, 'alice');
      expect(h.vm.socks!.host, login.host);
      expect(h.vm.clients.map((c) => c['name']), ['phone', 'laptop']);
      final actions = h.server.calls.map((c) => c.$1).toList();
      expect(
        actions.indexOf('root-password'),
        lessThan(actions.indexOf('create-user')),
      );
      final disable = h.server.calls.indexWhere(
        (c) => c.$1 == 'ssh-config' && c.$2[1] == 'no',
      );
      expect(
        h.server.calls
            .take(disable)
            .where((c) => c.$1 == 'preflight' && c.$3 == 'alice'),
        isNotEmpty,
      );
      expect(
        (await h.vm.vault.connection(login.host, login.port))!.user,
        'alice',
      );
      expect(
        (await h.vm.vault.account(login.host, login.port, 'root'))!.password,
        protectedAnswers.rootPassword,
      );
      expect(h.vm.log, isNot(contains(protectedAnswers.adminPassword)));
    },
  );
  test(
    'template answers execute exactly the same actions as manual answers',
    () async {
      final a = Harness(), b = Harness();
      addTearDown(a.vm.dispose);
      addTearDown(b.vm.dispose);
      await connect(a);
      await connect(b);
      final item = answers();
      expect(await b.vm.saveTemplate(item, protectedAnswers), isTrue);
      await a.vm.provision(item, protectedAnswers);
      await b.vm.provision(
        b.vm.templates.single,
        await b.vm.templateSecrets(item.name),
      );
      expect(
        b.server.calls.map((c) => [c.$1, c.$2, c.$3]).toList(),
        a.server.calls.map((c) => [c.$1, c.$2, c.$3]).toList(),
      );
    },
  );
  test(
    'failed administrator sudo keeps the original session and root access',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      h.server.denyAdmin = true;
      expect(await h.vm.provision(answers(), protectedAnswers), isFalse);
      expect(h.vm.ssh!.user, 'root');
      expect(h.backends.first.closed, isFalse);
      expect(
        h.server.calls.where((c) => c.$1 == 'ssh-config' && c.$2[1] == 'no'),
        isEmpty,
      );
      expect(h.vm.tasks.any((t) => t.state == TaskState.failed), isTrue);
      expect(h.vm.setupComplete, isFalse);
    },
  );
  test(
    'deferring VPN performs no installer, proxy or client actions',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      expect(
        await h.vm.provision(
          answers(awg: false, socks: false, clients: []),
          protectedAnswers,
        ),
        isTrue,
      );
      expect(
        h.server.calls.where(
          (c) => [
            'prepare-awg',
            'install-awg-configured',
            'socks-install',
            'add-client',
          ].contains(c.$1),
        ),
        isEmpty,
      );
      expect(h.vm.message, contains('install VPN later'));
    },
  );
  test('existing services and clients are preserved when applying a template again', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connect(h);
    await h.vm.provision(answers(), protectedAnswers);
    h.server.calls.clear();
    expect(await h.vm.provision(answers(), protectedAnswers), isTrue);
    expect(
      h.server.calls.where(
        (c) => [
          'socks-install',
          'install-awg-configured',
          'add-client',
        ].contains(c.$1),
      ),
      isEmpty,
    );
    expect(h.server.clients, {'phone', 'laptop'});
  });
  test('root cannot be disabled without a verified nonroot account', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connect(h);
    final count = h.server.calls.length;
    expect(
      await h.vm.provision(answers(admin: false), protectedAnswers),
      isFalse,
    );
    expect(h.server.calls.length, count);
    expect(await h.vm.disableRoot(), isFalse);
  });
  test(
    'switching endpoints clears all previous clients and SOCKS credentials',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      await h.vm.provision(answers(), protectedAnswers);
      expect(h.vm.clients, isNotEmpty);
      expect(h.vm.socks, isNotNull);
      expect(
        await h.vm.connect(
          const ConnectionDetails(
            host: '203.0.113.20',
            port: 22,
            user: 'root',
            password: 'test-other-placeholder',
          ),
          (_, _) async => true,
        ),
        isTrue,
      );
      expect(h.vm.clients, isEmpty);
      expect(h.vm.socks, isNull);
      expect(h.vm.log, isEmpty);
      expect(h.vm.ssh!.host, '203.0.113.20');
    },
  );
  test(
    'reconnect and client changes are blocked while provisioning runs',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      h.server.gate = Completer<void>();
      final pending = h.vm.provision(answers(), protectedAnswers);
      expect(await h.vm.connect(login, (_, _) async => true), isFalse);
      expect(await h.vm.addClient('other'), isFalse);
      h.server.gate!.complete();
      await pending;
    },
  );
  test('a kernel reboot requirement stops before changing accounts', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connect(h);
    h.server.state['reboot_required'] = true;
    expect(await h.vm.provision(answers(), protectedAnswers), isFalse);
    expect(
      h.server.calls.where(
        (c) => [
          'root-password',
          'create-user',
          'install-awg-configured',
        ].contains(c.$1),
      ),
      isEmpty,
    );
    expect(h.vm.error, contains('reboot'));
  });
  test(
    'root rotation updates saved access even if a later setup step fails',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connect(h);
      h.server.failAction = 'create-user';
      expect(await h.vm.provision(answers(), protectedAnswers), isFalse);
      expect(h.vm.ssh!.password, protectedAnswers.rootPassword);
      expect(
        (await h.vm.vault.connection(login.host, login.port))!.password,
        protectedAnswers.rootPassword,
      );
    },
  );
  test(
    'locked vault never writes secret answers into template metadata',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.store.fail = true;
      expect(await h.vm.saveTemplate(answers(), protectedAnswers), isFalse);
      expect(h.templates.records, isEmpty);
    },
  );
  test('capture login values before awaiting authentication', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.connectGate = Completer<void>();
    final pending = h.vm.connect(login, (_, _) async => true);
    expect(h.logins.single.user, 'root');
    h.connectGate!.complete();
    expect(await pending, isTrue);
    expect(h.vm.ssh!.user, 'root');
  });
}
