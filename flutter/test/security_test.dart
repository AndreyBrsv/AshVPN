import 'dart:async';
import 'dart:convert';

import 'package:ashapp/connection_details.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/server_workspace.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:ashapp/ssh_identity.dart';
import 'package:ashapp/workspace_controller.dart';
import 'package:ashapp/socks_tunnel.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

const login = ConnectionDetails(
  host: '203.0.113.10',
  port: 22,
  user: 'alice',
  password: 'test-security-placeholder',
);
ServerTemplate template({bool generate = false, bool denyPasswords = false}) =>
    ServerTemplate(
      name: 'Security',
      blockPing: false,
      disableRoot: false,
      installAwg: false,
      installSocks: false,
      awgPort: 585,
      clientNames: [],
      createAdmin: false,
      generateSshKey: generate,
      disablePasswordLogin: denyPasswords,
    );

class ClosedTunnelProbe extends Fake implements SocksTunnel {
  int closeCount = 0;
  @override
  Future<void> close() async {
    closeCount++;
  }
}

void main() {
  test('private SOCKS5 engine rejection cannot open a local tunnel', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(login, (_, _) async => true);
    h.server.failAction = 'socks-info';
    h.server.failureMessage =
        'Private SOCKS5 requires Docker Engine 28.0.0 or newer.';
    expect(await h.vm.startSocksTunnel(), isFalse);
    expect(h.vm.socksTunnel, isNull);
    expect(h.vm.error, contains('Docker Engine 28'));
  });

  test('repeated setup cannot start stopped configured proxies without a reviewed firewall refresh', () async {
    for (final service in ['vless', 'socks5']) {
      final h = Harness();
      addTearDown(h.vm.dispose);
      h.server.state.addAll({'${service}_configured': true, service: false});
      if (service == 'vless') {
        h.server.state['vless_port'] = 24443;
      }
      h.server.security['firewall'] = {'enabled': true, 'managed': true};
      await h.vm.connect(login, (_, _) async => true);
      final choice = service == 'vless' ? 'install_vless' : 'install_socks';
      final answers = ServerTemplate.fromJson({
        ...template().toJson(),
        choice: true,
        'configure_firewall': false,
      });
      const secrets = SetupSecrets(
        socksUser: 'proxy',
        socksPassword: 'test_proxy_placeholder',
      );
      expect(await h.vm.provision(answers, secrets), isFalse);
      expect(h.vm.error, contains('Configure firewall'));
      expect(
        h.server.calls.where(
          (c) => c.$1 == 'socks-control' || c.$1 == 'vless-control',
        ),
        isEmpty,
      );
      final reviewed = ServerTemplate.fromJson({
        ...answers.toJson(),
        'configure_firewall': true,
      });
      expect(await h.vm.provision(reviewed, secrets), isTrue);
      expect(h.server.state[service], isTrue);
      expect(
        h.server.calls.any(
          (c) =>
              c.$1 == 'security-stage' && c.$2[0].contains('"firewall":true'),
        ),
        isTrue,
      );
    }
  });
  test('forgotten recovery key is saved again before password denial; locked saving blocks staging', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(login, (_, _) async => true);
    expect(await h.vm.installSshIdentity('', '', generate: true), isTrue);
    expect(await h.vm.forgetPassword(), isTrue);
    h.store.fail = true;
    h.server.calls.clear();
    expect(
      await h.vm.applySecurity({'disable_passwords': true}, 'test-plan'),
      isFalse,
    );
    expect(h.server.calls.where((c) => c.$1 == 'security-stage'), isEmpty);
    h.store.fail = false;
    expect(
      await h.vm.applySecurity({'disable_passwords': true}, 'test-plan'),
      isTrue,
    );
    final saved = await h.vm.vault.connection(login.host, login.port);
    expect(saved!.privateKey == h.vm.ssh!.privateKey, isTrue);
  });

  test('direct key login with failed local saving cannot disable password authentication', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    final key = SshIdentity.generate().privateKey;
    h.store.fail = true;
    expect(
      await h.vm.connect(
        ConnectionDetails(
          host: login.host,
          port: login.port,
          user: login.user,
          password: '',
          privateKey: key,
        ),
        (_, _) async => true,
      ),
      isTrue,
    );
    expect(
      await h.vm.applySecurity({'disable_passwords': true}, 'test-plan'),
      isFalse,
    );
    expect(h.server.calls.where((c) => c.$1 == 'security-stage'), isEmpty);
  });

  test(
    'adding any protocol behind an owned firewall requires a reviewed refresh',
    () async {
      for (final service in ['install_awg', 'install_vless', 'install_socks']) {
        final h = Harness();
        addTearDown(h.vm.dispose);
        h.server.security['firewall'] = {'enabled': true, 'managed': true};
        await h.vm.connect(login, (_, _) async => true);
        final answers = ServerTemplate.fromJson({
          ...template().toJson(),
          service: true,
          'configure_firewall': false,
        });
        final secrets = const SetupSecrets(
          socksUser: 'proxy',
          socksPassword: 'test_proxy_placeholder',
        );
        expect(await h.vm.provision(answers, secrets), isFalse);
        expect(h.vm.error, contains('Configure firewall'));
        expect(
          h.server.calls.where(
            (c) => [
              'install-awg-configured',
              'install-vless',
              'socks-install',
            ].contains(c.$1),
          ),
          isEmpty,
        );
      }
    },
  );

  test('successful key and administrator swaps clear the old private tunnel and credentials', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await h.vm.connect(login, (_, _) async => true);
    final first = ClosedTunnelProbe();
    h.vm.socksTunnel = first;
    h.vm.socks = const ConnectionDetails(
      host: '127.0.0.1',
      port: 40000,
      user: 'proxy',
      password: 'test_proxy_placeholder',
    );
    expect(await h.vm.installSshIdentity('', '', generate: true), isTrue);
    expect(first.closeCount, 1);
    expect(h.vm.socksTunnel, isNull);
    expect(h.vm.socks, isNull);
    final second = ClosedTunnelProbe();
    h.vm.socksTunnel = second;
    expect(
      await h.vm.createAdministrator('bob', 'test_admin_placeholder'),
      isTrue,
    );
    expect(second.closeCount, 1);
    expect(h.vm.socksTunnel, isNull);
    expect(h.vm.socks, isNull);
  });
  test('new defaults, legacy templates and secret-free serialization', () {
    final settings = template();
    expect(settings.protectSsh, isTrue);
    expect(settings.configureFirewall, isTrue);
    expect(settings.disablePasswordLogin, isFalse);
    expect(settings.automaticUpdates, isFalse);
    expect(settings.socksAccess, 'public');
    final old = settings.toJson()
      ..remove('protect_ssh')
      ..remove('configure_firewall');
    expect(ServerTemplate.fromJson(old).protectSsh, isFalse);
    expect(ServerTemplate.fromJson(old).configureFirewall, isFalse);
    expect(
      () => ServerTemplate.fromJson({...old, 'automatic_updates': 1}),
      throwsFormatException,
    );
    expect(
      () => ServerTemplate.fromJson({...old, 'socks_access': 'shell-command'}),
      throwsFormatException,
    );
    expect(jsonEncode(settings.toJson()), isNot(contains('private_key')));
    expect(
      const SetupSecrets().validate(
        template(denyPasswords: true),
        activeUser: 'alice',
      ),
      contains('SSH private key'),
    );
  });

  test(
    'SSH keys are unique, parseable and never exposed by connection formatting',
    () {
      final a = SshIdentity.generate(), b = SshIdentity.generate();
      expect(a.privateKey, isNot(b.privateKey));
      expect(SshIdentity.parse(a.privateKey, '').publicKey, a.publicKey);
      final details = ConnectionDetails(
        host: login.host,
        port: 22,
        user: 'alice',
        password: '',
        privateKey: a.privateKey,
      );
      expect(
        details.format(revealPassword: true),
        isNot(contains(a.privateKey)),
      );
      expect(details.format(), contains('SSH key'));
      expect(() => SshIdentity.parse('invalid key', ''), throwsFormatException);
    },
  );

  test('generated key is saved before optional password denial and survives reconnect', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    expect(await h.vm.connect(login, (_, _) async => true), isTrue);
    expect(
      await h.vm.provision(
        template(generate: true, denyPasswords: true),
        const SetupSecrets(),
      ),
      isTrue,
    );
    expect(h.vm.ssh!.usesKey, isTrue);
    expect(
      (await h.vm.vault.connection(login.host, 22))!.privateKey,
      h.vm.ssh!.privateKey,
    );
    expect((h.server.state['ssh'] as Map)['passwordauthentication'], 'no');
    expect(h.vm.log, isNot(contains(h.vm.ssh!.privateKey)));
    expect(h.vm.tasks.every((task) => task.state == TaskState.done), isTrue);
    final jsonProfiles = h.profiles.records.map((p) => p.toJson()).toString();
    expect(jsonProfiles, isNot(contains('alice')));
    expect(jsonProfiles, isNot(contains(h.vm.ssh!.privateKey)));
  });

  test(
    'locked vault stops key-only migration before SSH policy changes',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login, (_, _) async => true);
      h.store.fail = true;
      expect(
        await h.vm.provision(
          template(generate: true, denyPasswords: true),
          const SetupSecrets(),
        ),
        isFalse,
      );
      expect((h.server.state['ssh'] as Map)['passwordauthentication'], 'yes');
      expect(h.server.calls.where((c) => c.$1 == 'security-stage'), isEmpty);
      expect(h.vm.ssh!.usesKey, isFalse);
      expect(h.vm.connected, isTrue);
    },
  );

  test(
    'password denial is refused without a key, before any stage command',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login, (_, _) async => true);
      expect(
        await h.vm.applySecurity({'disable_passwords': true}, 'test-plan'),
        isFalse,
      );
      expect(h.server.calls.where((c) => c.$1 == 'security-stage'), isEmpty);
    },
  );

  test(
    'failed fresh confirmation requests rollback and reports failure',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await h.vm.connect(login, (_, _) async => true);
      h.server.failAction = 'security-confirm';
      expect(
        await h.vm.applySecurity({'firewall': true}, 'test-plan'),
        isFalse,
      );
      expect(h.server.calls.any((c) => c.$1 == 'security-rollback'), isTrue);
      expect(h.vm.tasks.any((t) => t.state == TaskState.failed), isTrue);
      expect(h.vm.connected, isTrue);
    },
  );

  test('security actions stay bound to server and SSH port while selection changes', () async {
    final h = Harness();
    final workspace = ServerWorkspace(h.vm);
    addTearDown(() {
      workspace.dispose();
      workspace.closeSessions();
    });
    await h.vm.connect(login, (_, _) async => true);
    final b = workspace.create();
    await b.connect(
      const ConnectionDetails(
        host: '203.0.113.10',
        port: 2222,
        user: 'bob',
        password: 'other-test-placeholder',
      ),
      (_, _) async => true,
    );
    h.server.gate = Completer<void>();
    final pending = h.vm.applySecurity({'fail2ban': true}, 'test-plan');
    workspace.select(b);
    expect(
      await b.applySecurity({'automatic_updates': true}, 'test-plan'),
      isTrue,
    );
    h.server.gate!.complete();
    expect(await pending, isTrue);
    expect((h.server.security['fail2ban'] as Map)['enabled'], isTrue);
    final other = h.servers['203.0.113.10:2222']!;
    expect((other.security['fail2ban'] as Map)['enabled'], isFalse);
    expect((other.security['automatic_updates'] as Map)['enabled'], isTrue);
    expect(workspace.current, same(b));
  });
}
