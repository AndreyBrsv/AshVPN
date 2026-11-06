import 'dart:convert';

import 'package:ashapp/connection_details.dart';
import 'package:ashapp/credential_vault.dart';
import 'package:ashapp/provisioning_state.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

const login = ConnectionDetails(
  host: '203.0.113.10',
  port: 22,
  user: 'root',
  password: 'synthetic-current-access',
);
ServerTemplate plan({bool accounts = false, bool vpn = false}) =>
    ServerTemplate(
      name: 'Recovery',
      blockPing: false,
      disableRoot: false,
      installAwg: vpn,
      installSocks: false,
      awgPort: 585,
      clientNames: [],
      createAdmin: accounts,
      changeRootPassword: accounts,
      upgradePackages: accounts,
      protectSsh: false,
      configureFirewall: false,
      awgDeployment: 'host',
      sshPort: 22,
    );
const answers = SetupSecrets(
  rootPassword: 'synthetic-new-root',
  adminName: 'operator',
  adminPassword: 'synthetic-new-admin',
);

void main() {
  for (final action in ['root-password', 'create-user']) {
    test(
      'fresh committed $action marker overrides stale cache when failure reports are lost',
      () async {
        final h = Harness();
        addTearDown(h.vm.dispose);
        await h.vm.connect(login, (_, _) async => true);
        h.server.failAfterCredentialCommit = action;
        h.server.failFailureReports = true;
        expect(await h.vm.provision(plan(accounts: true), answers), isFalse);
        final draft = (await h.vm.recoveryDraft())!;
        final id = action == 'create-user' ? 'administrator' : 'root-password';
        expect(
          (h.vm.installation['steps'] as Map)[id]['credential_state'],
          isNull,
        );
        expect(
          (h.server.lifecycle['steps'] as Map)[id]['credential_state'],
          'committed',
        );
        h.server.failAfterCredentialCommit = null;
        h.server.failFailureReports = false;
        expect(
          await h.vm.provision(
            draft.answers,
            draft.secrets,
            resumeRunId: draft.runId,
          ),
          isTrue,
        );
        expect(h.server.calls.where((c) => c.$1 == action), hasLength(1));
        expect(h.vm.ssh!.user, 'operator');
      },
    );

    test(
      'fresh uncertain $action marker refuses replay even when the cached step has no marker',
      () async {
        final h = Harness();
        addTearDown(h.vm.dispose);
        await h.vm.connect(login, (_, _) async => true);
        h.server.failAfterCredentialCommit = action;
        h.server.failFailureReports = true;
        expect(await h.vm.provision(plan(accounts: true), answers), isFalse);
        final draft = (await h.vm.recoveryDraft())!;
        final id = action == 'create-user' ? 'administrator' : 'root-password';
        (h.server.lifecycle['steps'] as Map)[id]['credential_state'] =
            'started';
        expect(
          (h.vm.installation['steps'] as Map)[id]['credential_state'],
          isNull,
        );
        final count = h.server.calls.where((c) => c.$1 == action).length;
        h.server.failAfterCredentialCommit = null;
        h.server.failFailureReports = false;
        expect(
          await h.vm.provision(
            draft.answers,
            draft.secrets,
            resumeRunId: draft.runId,
          ),
          isFalse,
        );
        expect(h.vm.error, contains('current value is uncertain'));
        expect(h.server.calls.where((c) => c.$1 == action), hasLength(count));
      },
    );
  }

  for (final failure in ['ssh-config', 'administrator-sudo']) {
    test(
      'resume verifies administrator after committed password when $failure fails',
      () async {
        final h = Harness();
        addTearDown(h.vm.dispose);
        await h.vm.connect(login, (_, _) async => true);
        if (failure == 'ssh-config') {
          h.server.failAction = failure;
        } else {
          h.server.denyAdmin = true;
        }
        expect(await h.vm.provision(plan(accounts: true), answers), isFalse);
        final draft = (await h.vm.recoveryDraft())!;
        expect(
          (h.server.lifecycle['steps']
              as Map)['administrator']['credential_state'],
          'committed',
        );
        h.server.failAction = null;
        h.server.denyAdmin = false;
        expect(
          await h.vm.provision(
            draft.answers,
            draft.secrets,
            resumeRunId: draft.runId,
          ),
          isTrue,
        );
        expect(
          h.server.calls.where((c) => c.$1 == 'create-user'),
          hasLength(1),
        );
        expect(h.vm.ssh!.user, 'operator');
      },
    );
  }

  test('root password committed before command failure is remembered without being changed on resume', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(login, (_, _) async => true);
    h.server.failAfterCredentialCommit = 'root-password';
    expect(await h.vm.provision(plan(accounts: true), answers), isFalse);
    final draft = (await h.vm.recoveryDraft())!;
    h.server.failAfterCredentialCommit = null;
    expect(
      await h.vm.provision(
        draft.answers,
        draft.secrets,
        resumeRunId: draft.runId,
      ),
      isTrue,
    );
    expect(h.server.calls.where((c) => c.$1 == 'root-password'), hasLength(1));
    expect(
      (await h.vm.vault.account(login.host, login.port, 'root'))!.password,
      answers.rootPassword,
    );
  });

  for (final removed in ['ping', 'security']) {
    test(
      'resume reconstructs completed $removed removal after reconnect',
      () async {
        final h = Harness();
        addTearDown(h.vm.dispose);
        if (removed == 'ping') {
          h.server.state['icmp_blocked'] = true;
        } else {
          h.server.security['firewall'] = {'enabled': true, 'managed': true};
        }
        await h.vm.connect(login, (_, _) async => true);
        h.server.failAction = 'diagnostics';
        expect(await h.vm.provision(plan(), const SetupSecrets()), isFalse);
        final draft = (await h.vm.recoveryDraft())!;
        if (removed == 'security') {
          h.server.security['firewall'] = {'enabled': false, 'managed': false};
        }
        h.server.failAction = null;
        await h.vm.disconnect();
        await h.vm.connect(login, (_, _) async => true);
        expect(
          await h.vm.provision(
            draft.answers,
            draft.secrets,
            resumeRunId: draft.runId,
          ),
          isTrue,
        );
        expect((h.server.lifecycle['steps'] as Map)[removed]['state'], 'done');
      },
    );
  }
  test('resume keeps completed credentials and upgrades but rechecks actual services', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(login, (_, _) async => true);
    h.server.failAction = 'install-awg-configured';
    expect(
      await h.vm.provision(plan(accounts: true, vpn: true), answers),
      isFalse,
    );
    expect(h.vm.canResumeSetup, isTrue);
    final draft = await h.vm.recoveryDraft();
    expect(draft, isNotNull);
    expect(h.vm.ssh!.user, 'operator');
    h.server.failAction = null;
    expect(
      await h.vm.provision(
        draft!.answers,
        draft.secrets,
        resumeRunId: draft.runId,
      ),
      isTrue,
    );
    for (final action in ['root-password', 'create-user', 'upgrade']) {
      expect(
        h.server.calls.where((c) => c.$1 == action),
        hasLength(1),
        reason: action,
      );
    }
    expect(
      h.server.calls.where((c) => c.$1 == 'install-awg-configured'),
      hasLength(2),
    );
    expect(h.vm.setupComplete, isTrue);
    expect(h.server.lifecycle['status'], 'complete');
  });

  test(
    'server plan contains no credentials or administrator/device names',
    () async {
      final value = ServerTemplate.fromJson({
        ...plan(accounts: true, vpn: true).toJson(),
        'client_names': ['PhonePrivate'],
      });
      final intent = jsonEncode(serverSetupIntent(value));
      for (final forbidden in [
        '"root_password":',
        '"admin_name":',
        '"connection_password":',
        '"private_key":',
        '"client_names":',
        'PhonePrivate',
        'operator',
      ]) {
        expect(intent, isNot(contains(forbidden)));
      }
      expect(serverSetupIntent(value)['awg_client_count'], 1);
    },
  );

  test(
    'failed diagnostics prevents completed setup despite active services',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login, (_, _) async => true);
      h.server.checks = [
        {
          'id': 'firewall-port',
          'status': 'fail',
          'detail': 'VPN port blocked.',
        },
      ];
      expect(await h.vm.provision(plan(), const SetupSecrets()), isFalse);
      expect(h.vm.setupComplete, isFalse);
      expect(h.vm.error, contains('firewall-port'));
      expect(h.server.lifecycle['status'], 'failed');
    },
  );

  test(
    'external connectivity limitation is visible without blocking local checks',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login, (_, _) async => true);
      h.server.checks.add({
        'id': 'external-connectivity',
        'status': 'unknown',
        'required': false,
        'detail': 'External client needed.',
      });
      expect(await h.vm.provision(plan(), const SetupSecrets()), isTrue);
      expect(h.vm.diagnosticChecks.last['status'], 'unknown');
    },
  );

  test('failed optional inventory preserves authenticated SSH and reports unknown state', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.server.failAction = 'status';
    expect(await h.vm.connect(login, (_, _) async => true), isTrue);
    expect(h.vm.connected, isTrue);
    expect(h.vm.server, isEmpty);
    expect(h.vm.inspectionWarnings, isNotEmpty);
    h.server.failAction = null;
    expect(await h.vm.refresh(), isTrue);
    expect(h.vm.inspectionWarnings, isEmpty);
  });

  test(
    'protected recovery is isolated by host and SSH port and removed on forget',
    () async {
      final vault = CredentialVault(MemorySecrets());
      final a = ProvisioningDraft(
        runId: 'run-a',
        answers: plan(),
        secrets: answers,
      );
      final b = ProvisioningDraft(
        runId: 'run-b',
        answers: plan(),
        secrets: const SetupSecrets(),
      );
      await vault.saveSetup(login.host, 22, a);
      await vault.saveSetup(login.host, 2222, b);
      await vault.forgetSetup(login.host, 22);
      expect(await vault.setup(login.host, 22), isNull);
      expect((await vault.setup(login.host, 2222))!.runId, 'run-b');
    },
  );

  test('reset requires the reviewed endpoint and confirms SSH before removing services', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(login, (_, _) async => true);
    final reviewed = (await h.vm.previewReset())!;
    expect(
      await h.vm.resetServer({...reviewed, 'endpoint': '203.0.113.33:2222'}),
      isFalse,
    );
    expect(h.server.calls.where((c) => c.$1 == 'reset'), isEmpty);
    expect(await h.vm.resetServer(reviewed), isTrue);
    expect(
      h.server.calls.indexWhere((c) => c.$1 == 'security-confirm'),
      lessThan(h.server.calls.indexWhere((c) => c.$1 == 'reset')),
    );
    expect(h.vm.ssh!.password, login.password);
    expect(h.vm.connected, isTrue);
    expect(h.vm.installation['status'], 'reset');
  });

  test('unchecked owned service stops and selecting it starts the existing VPN without reinstalling', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    h.server.state.addAll({
      'awg': true,
      'awg_configured': true,
      'kernel': true,
      'interface': 'awg0',
      'awg_deployment': 'host',
      'awg_port': 585,
    });
    h.server.lifecycle['owned_services'] = {'awg': true};
    await h.vm.connect(login, (_, _) async => true);
    expect(await h.vm.provision(plan(), const SetupSecrets()), isTrue);
    expect(h.server.state['awg'], isFalse);
    expect(await h.vm.provision(plan(vpn: true), const SetupSecrets()), isTrue);
    expect(h.server.state['awg'], isTrue);
    expect(
      h.server.calls.where((c) => c.$1 == 'awg-control').map((c) => c.$2),
      [
        ['stop'],
        ['start'],
      ],
    );
    expect(
      h.server.calls.where((c) => c.$1.startsWith('install-awg')),
      isEmpty,
    );
  });

  test(
    'unchecked service does not stop an unowned existing installation',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.state.addAll({
        'awg': true,
        'awg_configured': true,
        'kernel': true,
        'interface': 'awg0',
      });
      await h.vm.connect(login, (_, _) async => true);
      expect(await h.vm.provision(plan(), const SetupSecrets()), isTrue);
      expect(h.server.calls.where((c) => c.$1 == 'awg-control'), isEmpty);
      expect(h.server.state['awg'], isTrue);
    },
  );

  test('resume rejects changed protected answers before replaying any credential operation', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(login, (_, _) async => true);
    h.server.failAction = 'install-awg-configured';
    expect(
      await h.vm.provision(plan(accounts: true, vpn: true), answers),
      isFalse,
    );
    final draft = (await h.vm.recoveryDraft())!;
    final oldCalls = h.server.calls.length;
    expect(
      await h.vm.provision(
        draft.answers,
        const SetupSecrets(
          rootPassword: 'different-placeholder',
          adminName: 'operator',
          adminPassword: 'different-admin-placeholder',
        ),
        resumeRunId: draft.runId,
      ),
      isFalse,
    );
    expect(
      h.server.calls
          .skip(oldCalls)
          .where(
            (c) => {
              'root-password',
              'create-user',
              'lifecycle-begin',
            }.contains(c.$1),
          ),
      isEmpty,
    );
  });
}
