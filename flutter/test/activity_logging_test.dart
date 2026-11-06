import 'dart:async';

import 'package:ashapp/connection_details.dart';
import 'package:ashapp/remote_backend.dart';
import 'package:ashapp/credential_vault.dart';
import 'package:ashapp/ssh_connection.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:ashapp/workspace_controller.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';
import 'remote_backend_test.dart' show TestClient;

class LoggingClient extends TestClient {
  final finished = Completer<void>();
  @override
  Future<void> get done => finished.future;
  @override
  Future<void> close() async {
    if (!finished.isCompleted) finished.complete();
  }
}

const login = ConnectionDetails(
  host: '203.0.113.10',
  port: 22,
  user: 'root',
  password: 'synthetic-login-placeholder',
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('backend partial normalization and controller normalization cannot reveal a credential', () async {
    final h = Harness();
    final client = LoggingClient();
    final vm = WorkspaceController(
      profilesRepository: h.profiles,
      templatesRepository: h.templates,
      vault: CredentialVault(h.store),
      connector: ({
        required host,
        required port,
        required username,
        required password,
        required confirmHost,
      }) async => SshConnection.fromClient(client),
      backendFactory: RemoteBackend.new,
    );
    addTearDown(vm.dispose);
    const controlled = ConnectionDetails(
      host: '203.0.113.10',
      port: 22,
      user: 'root',
      password: 'synthetic-\x1B[31mcontrol-\x07placeholder',
    );
    expect(await vm.connect(controlled, (_, _) async => true), isTrue);
    client.rawError = 'ERROR: Echo: ${controlled.password}\n';
    expect(await vm.diagnoseSecurity(), isFalse);
    await Future<void>.delayed(Duration.zero);
    for (final value in [
      controlled.password,
      'synthetic-control-placeholder',
      'synthetic-control-\x07placeholder',
    ]) {
      expect(vm.log, isNot(contains(value)));
      expect(vm.error, isNot(contains(value)));
    }
    expect(vm.log, contains('Echo: ********'));
  });
  test('raw and terminal-normalized credentials are both masked', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    const controlled = ConnectionDetails(
      host: '203.0.113.10',
      port: 22,
      user: 'root',
      password: 'synthetic-\x1B[31mcontrol-\x07placeholder',
    );
    await h.vm.connect(controlled, (_, _) async => true);
    h.backends.last.output.add('Echo: ${controlled.password}');
    h.backends.last.output.add('Echo: synthetic-control-placeholder');
    await Future<void>.delayed(Duration.zero);
    expect(h.vm.log, isNot(contains('synthetic-')));
    expect(h.vm.log, isNot(contains('control-placeholder')));
    expect(h.vm.log, contains('Echo: ********'));
  });
  test(
    'setup failure preserves completed steps and identifies the failing step',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login, (_, _) async => true);
      h.server.failAction = 'security-preview';
      h.server.failureMessage = 'Synthetic security policy refusal.';
      final answers = ServerTemplate(
        name: 'Activity test',
        blockPing: false,
        disableRoot: false,
        installAwg: true,
        installSocks: false,
        awgPort: 585,
        clientNames: [],
        createAdmin: false,
      );
      expect(await h.vm.provision(answers, const SetupSecrets()), isFalse);
      expect(h.vm.tasks.first.state, TaskState.done);
      expect(h.vm.tasks[1].state, TaskState.failed);
      expect(h.vm.log, contains('[SETUP] Stopped at: Inspect server.'));
      expect(h.vm.log, contains('Synthetic security policy refusal.'));
      expect(
        h.server.calls.any((call) => call.$1 == 'install-awg-configured'),
        isFalse,
      );
    },
  );

  test('activity copy source masks login, keys and VPN access links', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(login, (_, _) async => true);
    final lines = [
      'password=${login.password}',
      'PrivateKey = synthetic-private-placeholder',
      'vless://01234567-89ab-cdef-0123-456789abcdef@example.test',
      'vpn://synthetic_encoded_private_access-placeholder',
      '\x1B[31mSSH remains available\x1B[0m',
    ];
    for (final line in lines) {
      h.backends.last.output.add(line);
    }
    await Future<void>.delayed(Duration.zero);
    expect(h.vm.log, isNot(contains(login.password)));
    expect(h.vm.log, isNot(contains('synthetic-private-placeholder')));
    expect(h.vm.log, isNot(contains('01234567-89ab-cdef-0123-456789abcdef')));
    expect(h.vm.log, isNot(contains('synthetic_encoded_private_access')));
    expect(h.vm.log, contains('vpn://********'));
    expect(h.vm.log, isNot(contains('\x1B')));
    expect(h.vm.log, contains('SSH remains available'));
  });
}
