import 'dart:async';
import 'dart:io';

import 'package:ashapp/connection_details.dart';
import 'package:ashapp/credential_vault.dart';
import 'package:ashapp/server_profiles.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/server_workspace.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:ashapp/template_repository.dart';
import 'package:ashapp/workspace_controller.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as path;

import 'support/fakes.dart';

ConnectionDetails login(String host, [int port = 22, String user = 'root']) =>
    ConnectionDetails(
      host: host,
      port: port,
      user: user,
      password: 'test-login-placeholder',
    );
ServerTemplate template(bool ping) => ServerTemplate(
  name: 'Friends',
  blockPing: ping,
  disableRoot: false,
  installAwg: false,
  installSocks: false,
  awgPort: 585,
  clientNames: [],
);

void main() {
  test('failed secret deletion survives restart and retries without plaintext metadata', () async {
    final directory = await Directory.systemTemp.createTemp('ashapp_cleanup_');
    addTearDown(() => directory.delete(recursive: true));
    final h = Harness();
    final file = File(path.join(directory.path, 'templates.json'));
    final repository = TemplateRepository(file);
    WorkspaceController create() => WorkspaceController(
      profilesRepository: h.profiles,
      templatesRepository: repository,
      vault: CredentialVault(h.store),
    );
    final first = create();
    await first.saveTemplate(
      template(false),
      const SetupSecrets(adminPassword: 'test-cleanup-placeholder'),
    );
    h.store.failDelete = true;
    expect(await first.removeTemplate('Friends'), isTrue);
    expect(first.templateCleanupPending, isTrue);
    expect(await repository.load(), isEmpty);
    expect(
      await file.readAsString(),
      isNot(contains('test-cleanup-placeholder')),
    );
    first.dispose();
    final restarted = create();
    addTearDown(restarted.dispose);
    await restarted.initialize();
    expect(restarted.templateCleanupPending, isTrue);
    expect(h.store.values, isNotEmpty);
    h.store.failDelete = false;
    expect(await restarted.retryTemplateCleanup(), isTrue);
    expect(h.store.values, isEmpty);
    expect(await repository.pendingDeletions(), isEmpty);
    expect(restarted.templateCleanupPending, isFalse);
  });
  test(
    'the same endpoint cannot acquire two live or connecting sessions',
    () async {
      final h = Harness();
      final group = ServerWorkspace(h.vm);
      addTearDown(() {
        group.dispose();
        group.closeSessions();
      });
      final b = group.create();
      h.connectGate = Completer<void>();
      final first = h.vm.connect(login('203.0.113.10'), (_, _) async => true);
      await Future<void>.delayed(Duration.zero);
      expect(
        await b.connect(login('203.0.113.10'), (_, _) async => true),
        isFalse,
      );
      expect(h.logins, hasLength(1));
      h.connectGate!.complete();
      expect(await first, isTrue);
      expect(
        await b.connect(login('203.0.113.10'), (_, _) async => true),
        isFalse,
      );
      expect(h.vm.connected, isTrue);
      expect(h.logins, hasLength(1));
    },
  );
  test(
    'overlapping old and new passwords are fully redacted in activity output',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login('203.0.113.10'), (_, _) async => true);
      await h.vm.changeRootPassword('test-login-placeholder_extended');
      h.backends.last.output.add(
        'server said: test-login-placeholder_extended',
      );
      await Future<void>.delayed(Duration.zero);
      expect(h.vm.log, contains('server said: ********'));
      expect(h.vm.log, isNot(contains('extended')));
    },
  );
  test(
    'profile metadata failure cannot prevent saving a changed root password',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login('203.0.113.10'), (_, _) async => true);
      h.profiles.fail = true;
      expect(await h.vm.changeRootPassword('test-rotated-placeholder'), isTrue);
      expect(
        (await h.vm.vault.connection('203.0.113.10', 22))!.password,
        'test-rotated-placeholder',
      );
      expect(h.vm.error, contains('local saving failed'));
    },
  );
  test('independent servers keep sessions, credentials, clients and errors isolated', () async {
    final h = Harness();
    final group = ServerWorkspace(h.vm);
    addTearDown(() {
      group.dispose();
      group.closeSessions();
    });
    final a = h.vm, b = group.create();
    expect(
      await a.connect(login('203.0.113.10'), (_, _) async => true),
      isTrue,
    );
    expect(
      await b.connect(login('203.0.113.20'), (_, _) async => true),
      isTrue,
    );
    h.server.state.addAll({'awg': true, 'kernel': true});
    group.select(a);
    expect(await a.addClient('phone'), isTrue);
    group.select(b);
    expect(a.connected, isTrue);
    expect(a.clients.single['name'], 'phone');
    expect(b.clients, isEmpty);
    h.servers['203.0.113.20']!.failAction = 'status';
    expect(await b.refresh(), isTrue);
    expect(b.inspectionWarnings, isNotEmpty);
    expect(a.inspectionWarnings, isEmpty);
    expect(a.error, isEmpty);
    expect(await b.disconnect(), isTrue);
    expect(a.connected, isTrue);
    expect(
      (await a.savedLogin(const ServerProfile(ip: '203.0.113.10', sshPort: 22)))
          ?.host,
      '203.0.113.10',
    );
  });

  test('same IP with different SSH ports is two independent servers', () async {
    final h = Harness();
    final sessions = ServerWorkspace(h.vm);
    addTearDown(() {
      sessions.dispose();
      sessions.closeSessions();
    });
    final b = sessions.create();
    await h.vm.connect(login('203.0.113.10'), (_, _) async => true);
    await b.connect(login('203.0.113.10', 2222), (_, _) async => true);
    expect(
      sessions.find(const ServerProfile(ip: '203.0.113.10', sshPort: 22)),
      same(h.vm),
    );
    expect(
      sessions.find(const ServerProfile(ip: '203.0.113.10', sshPort: 2222)),
      same(b),
    );
    await b.changeRootPassword('test-port2222-placeholder');
    expect(h.vm.ssh!.password, 'test-login-placeholder');
    expect(
      (await h.vm.vault.connection('203.0.113.10', 22))!.password,
      'test-login-placeholder',
    );
    expect(
      (await b.vault.connection('203.0.113.10', 2222))!.password,
      'test-port2222-placeholder',
    );
  });

  test('switching to another server leaves in-flight work on its original endpoint', () async {
    final h = Harness();
    final sessions = ServerWorkspace(h.vm);
    addTearDown(() {
      sessions.dispose();
      sessions.closeSessions();
    });
    final b = sessions.create();
    await h.vm.connect(login('203.0.113.10'), (_, _) async => true);
    await b.connect(login('203.0.113.20'), (_, _) async => true);
    h.server.gate = Completer<void>();
    final pending = h.vm.blockPing(true);
    sessions.select(b);
    expect(await b.refresh(), isTrue);
    expect(h.vm.busy, isTrue);
    h.server.gate!.complete();
    expect(await pending, isTrue);
    expect(h.vm.server['icmp_blocked'], isTrue);
    expect(b.server['icmp_blocked'], isFalse);
  });

  for (final fail in ['ssh-config', 'preflight']) {
    test(
      'changed active administrator password survives failed $fail',
      () async {
        final h = Harness();
        addTearDown(h.vm.dispose);
        await h.vm.connect(
          login('203.0.113.10', 22, 'alice'),
          (_, _) async => true,
        );
        h.server.failAction = fail;
        expect(
          await h.vm.createAdministrator('alice', 'test-new-admin-placeholder'),
          isFalse,
        );
        expect(h.vm.connected, isTrue);
        expect(h.vm.ssh!.password, 'test-new-admin-placeholder');
        expect(
          (await h.vm.vault.connection('203.0.113.10', 22))!.password,
          'test-new-admin-placeholder',
        );
      },
    );
  }

  test(
    'failed metadata replacement preserves the old template secret generation',
    () async {
      final dir = await Directory.systemTemp.createTemp('ashapp_atomic_');
      addTearDown(() => dir.delete(recursive: true));
      final h = Harness(), file = File(path.join(dir.path, 'templates.json'));
      final repository = TemplateRepository(file);
      final vm = WorkspaceController(
        profilesRepository: h.profiles,
        templatesRepository: repository,
        vault: CredentialVault(h.store),
      );
      addTearDown(vm.dispose);
      expect(
        await vm.saveTemplate(
          template(false),
          const SetupSecrets(adminPassword: 'test-original-placeholder'),
        ),
        isTrue,
      );
      final original = await file.readAsString();
      final ref = (await repository.load()).single.credentialsRef!;
      await file.writeAsString('corrupt');
      expect(
        await vm.saveTemplate(
          template(true),
          const SetupSecrets(adminPassword: 'test-overwrite-placeholder'),
        ),
        isFalse,
      );
      expect(
        (await vm.vault.template(ref)).adminPassword,
        'test-original-placeholder',
      );
      expect(h.store.values.length, 1);
      await file.writeAsString(original);
      expect(
        (await vm.templateSecrets('Friends')).adminPassword,
        'test-original-placeholder',
      );
    },
  );

  test(
    'successful replacement deletes only the superseded protected generation',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.saveTemplate(
        template(false),
        const SetupSecrets(adminPassword: 'test-one-placeholder'),
      );
      await h.vm.saveTemplate(
        template(true),
        const SetupSecrets(adminPassword: 'test-two-placeholder'),
      );
      expect(h.store.values.length, 1);
      expect(
        (await h.vm.templateSecrets('Friends')).adminPassword,
        'test-two-placeholder',
      );
      await h.vm.removeTemplate('Friends');
      expect(h.store.values, isEmpty);
    },
  );
}
