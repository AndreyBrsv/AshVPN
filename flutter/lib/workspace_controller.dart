import 'dart:async';
import 'dart:math';
import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'connection_details.dart';
import 'client_configuration.dart';
import 'credential_vault.dart';
import 'remote_backend.dart';
import 'server_profiles.dart';
import 'server_template.dart';
import 'setup_secrets.dart';
import 'ssh_connection.dart';
import 'template_repository.dart';
import 'vless_connection.dart';
import 'ssh_identity.dart';
import 'socks_tunnel.dart';

typedef SshConnector = Future<SshConnection> Function({
  required String host,
  required int port,
  required String username,
  required String password,
  required ConfirmHost confirmHost,
});

enum TaskState { waiting, running, done, failed }

class SetupTask {
  SetupTask(this.label);
  final String label;
  TaskState state = TaskState.waiting;
}

/// One authenticated endpoint and one serialized command flow at a time.
class WorkspaceController extends ChangeNotifier {
  WorkspaceController({
    required this.profilesRepository,
    required this.templatesRepository,
    required this.vault,
    this.connector = SshConnection.connect,
    this.backendFactory = RemoteBackend.new,
    this.keyConnector = SshConnection.connectWithKey,
  });
  final ServerProfiles profilesRepository;
  final TemplateRepository templatesRepository;
  final CredentialVault vault;
  final SshConnector connector;
  final Future<SshConnection> Function(ConnectionDetails, ConfirmHost)
  keyConnector;
  final RemoteBackend Function(SshConnection, String) backendFactory;

  /// The owning workspace reserves an endpoint before authentication starts.
  void Function(ConnectionDetails)? beforeConnect;
  bool Function()? canStartOperation;
  List<ServerProfile> profiles = [];
  List<ServerTemplate> templates = [];
  ConnectionDetails? ssh, socks, savedAccount;
  RemoteBackend? _backend;
  StreamSubscription<String>? _output;
  bool busy = false, remember = true, setupComplete = false, _disposed = false;
  String message = 'Choose a server to get started.', error = '', log = '';
  Map<String, dynamic> server = {};
  Map<String, dynamic>? security;
  String securityError = '';
  bool securityPending = false;
  SocksTunnel? socksTunnel;
  Timer? _progressTimer;
  final _operationClock = Stopwatch();
  Duration get elapsed => _operationClock.elapsed;
  List<Map<String, dynamic>> clients = [], users = [];
  List<String> clientWarnings = [];
  String clientsError = '';
  List<SetupTask> tasks = [];
  bool templateCleanupPending = false;
  final _secrets = <String>{};
  bool get connected =>
      _backend != null && !_backend!.connection.client.isClosed;
  void _notify() {
    if (!_disposed) notifyListeners();
  }

  String _redact(String line) {
    var safe = line;
    final secrets = _secrets.where((s) => s.isNotEmpty).toList()
      ..sort((a, b) => b.length.compareTo(a.length));
    for (final secret in secrets) {
      safe = safe.replaceAll(secret, '********');
    }
    return safe;
  }

  void _append(String line) {
    log += '${_redact(line)}\n';
    if (log.length > 100000) log = log.substring(log.length - 100000);
    _notify();
  }

  Future<bool> _guard(Future<void> Function() body) async {
    if (busy || _disposed) return false;
    if (canStartOperation?.call() == false) {
      error = 'An app update is starting. Server operations are paused.';
      _notify();
      return false;
    }
    busy = true;
    tasks = [];
    _operationClock
      ..reset()
      ..start();
    _progressTimer = Timer.periodic(
      const Duration(seconds: 1),
      (_) => _notify(),
    );
    error = '';
    _notify();
    try {
      await body();
      return true;
    } catch (e) {
      error = _redact(switch (e) {
        TimeoutException() => 'The command timed out. Some changes may already have completed. Refresh status before retrying.',
        StateError() => e.message.toString(),
        FormatException() => e.message,
        _ => 'The operation failed. Check the server connection and activity details.',
      });
      _append(error);
      return false;
    } finally {
      busy = false;
      _operationClock.stop();
      _progressTimer?.cancel();
      _notify();
    }
  }

  Future<void> initialize() async {
    await _guard(() async {
      profiles = await profilesRepository.load();
      templates = await templatesRepository.load();
      await _cleanupTemplateSecrets();
    });
  }

  Future<ConnectionDetails?> savedLogin(ServerProfile profile) =>
      vault.connection(profile.ip, profile.sshPort);
  Future<SetupSecrets> templateSecrets(String name) async {
    templates = await templatesRepository.load();
    final template = templates.firstWhere((t) => t.name == name);
    return vault.template(template.credentialsRef ?? name);
  }

  Future<bool> saveTemplate(ServerTemplate template, SetupSecrets secrets) =>
      _guard(() async {
        final random = Random.secure();
        final ref = List.generate(
          16,
          (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
        ).join();
        await vault.saveTemplate(ref, secrets);
        try {
          await templatesRepository.upsert(template.withCredentialsRef(ref));
        } catch (_) {
          await vault.deleteTemplate(ref);
          rethrow;
        }
        await _cleanupTemplateSecrets();
        templates = await templatesRepository.load();
        message = 'Template saved on this device.';
      });
  Future<bool> removeTemplate(String name) => _guard(() async {
    await templatesRepository.remove(name);
    await _cleanupTemplateSecrets();
    templates = await templatesRepository.load();
    message = templateCleanupPending
        ? 'Template removed. Protected cleanup is pending.'
        : 'Template deleted.';
  });

  Future<void> _cleanupTemplateSecrets() async {
    for (final ref in await templatesRepository.pendingDeletions()) {
      try {
        await vault.deleteTemplate(ref);
        await templatesRepository.acknowledgeDeletion(ref);
      } catch (_) {
        // Keep only the opaque reference on disk and retry after restart/unlock.
      }
    }
    templateCleanupPending =
        (await templatesRepository.pendingDeletions()).isNotEmpty;
    if (templateCleanupPending) {
      _append(
        'Unused protected answers could not be erased. Unlock the OS vault and retry protected cleanup.',
      );
    }
  }

  Future<bool> retryTemplateCleanup() => _guard(() async {
    await _cleanupTemplateSecrets();
    message = templateCleanupPending
        ? 'Protected cleanup is still pending.'
        : 'Unused protected answers removed.';
  });
  Future<bool> removeProfile(ServerProfile profile) => _guard(() async {
    await vault.forgetConnection(profile.ip, profile.sshPort);
    await profilesRepository.remove(profile);
    profiles = await profilesRepository.load();
    message = 'Removed from this device. The server was not changed.';
  });
  Future<bool> forgetPassword() => _guard(() async {
    final details = _login;
    await vault.forgetConnection(details.host, details.port);
    remember = false;
    message = 'Saved SSH credentials removed. The current session stays open.';
  });

  ConnectionDetails get _login =>
      ssh ?? (throw StateError('Connect to a server first.'));
  RemoteBackend get _active =>
      connected ? _backend! : (throw StateError('Connect to a server first.'));

  Future<SshConnection> _connectUsing(
    ConnectionDetails details,
    ConfirmHost confirmHost,
  ) => details.usesKey
      ? keyConnector(details, confirmHost)
      : connector(
          host: details.host,
          port: details.port,
          username: details.user,
          password: details.password,
          confirmHost: confirmHost,
        );

  Future<bool> connect(ConnectionDetails details, ConfirmHost confirmHost) =>
      _guard(() async {
        if (details.host.isEmpty ||
            details.user.isEmpty ||
            (details.password.isEmpty && !details.usesKey) ||
            details.port < 1 ||
            details.port > 65535) {
          throw StateError('Enter the address, port, username and password.');
        }
        ServerProfile.fromJson({'ip': details.host, 'ssh_port': details.port});
        if (details.usesKey) {
          SshIdentity.parse(details.privateKey, details.keyPassphrase);
        }
        beforeConnect?.call(details);
        message = 'Connecting…';
        _notify();
        final next = await _connectUsing(details, confirmHost);
        final backend = backendFactory(next, details.user);
        try {
          final preflight = await backend.run('preflight');
          final inspected = preflight['python'] == false
              ? <String, dynamic>{}
              : await backend.run('status');
          if (_disposed) throw StateError('The app was closed.');
          await _adopt(backend, details);
          server = inspected;
          if (preflight['python'] != false) {
            try {
              await _refresh();
            } catch (_) {
              _append(
                'Connected. Some server details could not be read; use Refresh status after installing base packages.',
              );
            }
          }
          message = 'Connected to ${details.host}.';
          await _rememberLogin();
        } catch (_) {
          if (!identical(_backend, backend)) {
            await backend.close();
            await next.close();
          }
          rethrow;
        }
      });

  Future<void> _adopt(RemoteBackend next, ConnectionDetails details) async {
    await _output?.cancel();
    final old = _backend;
    await socksTunnel?.close();
    socksTunnel = null;
    _backend = next;
    ssh = details;
    socks = null;
    savedAccount = null;
    clients = [];
    clientWarnings = [];
    clientsError = '';
    users = [];
    server = {};
    security = null;
    securityPending = false;
    setupComplete = false;
    tasks = [];
    log = '';
    _secrets.clear();
    _secrets.add(details.password);
    _secrets.addAll([details.privateKey, details.keyPassphrase]);
    _output = next.output.stream.listen(_append);
    _watchConnection(next);
    if (old != null && !identical(old, next)) {
      await old.close();
      await old.connection.close();
    }
  }

  Future<void> _rememberLogin({ConnectionDetails? additional}) async {
    final details = _login;
    try {
      // Save remotely changed credentials before fallible profile metadata.
      if (remember) {
        await vault.saveConnection(details, additional: additional);
      } else {
        await vault.forgetConnection(details.host, details.port);
      }
      await profilesRepository.upsert(
        ServerProfile(ip: details.host, sshPort: details.port),
      );
      profiles = await profilesRepository.load();
    } catch (_) {
      error = 'Server access is active, but local saving failed. Copy the credentials before closing the app.';
      _append(error);
    }
  }

  void _watchConnection(RemoteBackend backend) {
    void lost() {
      if (_disposed || !identical(_backend, backend)) return;
      _backend = null;
      _output?.cancel();
      _output = null;
      socks = null;
      savedAccount = null;
      clients = [];
      clientWarnings = [];
      clientsError = '';
      users = [];
      server = {};
      security = null;
      unawaited(socksTunnel?.close());
      socksTunnel = null;
      setupComplete = false;
      message = 'SSH connection closed. Reconnect to inspect the server.';
      unawaited(backend.close());
      _notify();
    }

    unawaited(
      backend.connection.client.done.then(
        (_) => lost(),
        onError: (Object _, StackTrace _) => lost(),
      ),
    );
  }

  Future<bool> disconnect() => _guard(() async {
    await socksTunnel?.close();
    socksTunnel = null;
    await _output?.cancel();
    _output = null;
    final old = _backend;
    _backend = null;
    await old?.close();
    await old?.connection.close();
    ssh = null;
    socks = null;
    savedAccount = null;
    clients = [];
    clientWarnings = [];
    clientsError = '';
    users = [];
    server = {};
    security = null;
    log = '';
    tasks = [];
    _secrets.clear();
    setupComplete = false;
    message = 'Disconnected.';
  });

  Future<void> _refresh() async {
    server = await _active.run('status');
    clients = [];
    clientWarnings = [];
    clientsError = '';
    try {
      final result = await _active.run('clients');
      clients = List<Map<String, dynamic>>.from(
        result['clients'] as List? ?? [],
      );
      for (final row in clients) {
        if (row['source'] == VlessConnection.source &&
            row['public_key'] is String) {
          _secrets.add(row['public_key'] as String);
        }
      }
      clientWarnings = List<String>.from(result['warnings'] as List? ?? []);
    } catch (_) {
      clientsError = 'The VPN client list could not be loaded. Check the connection and refresh. Existing clients have not been changed.';
      _append(clientsError);
    }
    final result = await _active.run('users');
    users = List<Map<String, dynamic>>.from(result['users'] as List? ?? []);
    await _securityStatus();
  }

  Future<void> _securityStatus() async {
    security = null;
    securityError = '';
    try {
      security = await _active.run('security-status');
      securityPending = security?['pending'] == true;
    } catch (_) {
      securityError = 'Security status is unknown. Check the connection and retry diagnostics.';
    }
  }

  Future<bool> diagnoseSecurity() => _guard(() async {
    message = 'Checking server security…';
    await _securityStatus();
    if (security == null) throw StateError(securityError);
    message = 'Security diagnostics refreshed.';
  });

  Future<Map<String, dynamic>?> previewSecurity(
    Map<String, bool> changes,
  ) async {
    Map<String, dynamic>? result;
    await _guard(() async {
      result = await _active.run('security-preview', [jsonEncode(changes)]);
    });
    return result;
  }

  Future<void> _securityApply(
    Map<String, bool> changes, {
    String? expected,
  }) async {
    if (changes['disable_passwords'] == true && !_login.usesKey) {
      throw StateError(
        'Connect with a verified SSH key before disabling password login.',
      );
    }
    if (changes['disable_root'] == true && _login.user == 'root') {
      throw StateError(
        'Connect as an administrator before disabling root SSH.',
      );
    }
    // Verify the recovery credential before staging any network policy.
    final proof = await _connectUsing(_login, (_, _) async => false);
    final proofBackend = backendFactory(proof, _login.user);
    try {
      await proofBackend.run('preflight');
    } finally {
      await proofBackend.close();
      await proof.close();
    }
    if (changes['disable_passwords'] == true) {
      final recovery = _login;
      await vault.saveConnection(recovery);
      final saved = await vault.connection(recovery.host, recovery.port);
      if (saved == null ||
          saved.user != recovery.user ||
          saved.privateKey != recovery.privateKey ||
          saved.keyPassphrase != recovery.keyPassphrase) {
        throw StateError(
          'Save and verify the active SSH key in the OS vault before disabling passwords.',
        );
      }
      remember = true;
    }
    final plan = expected == null
        ? await _active.run('security-preview', [jsonEncode(changes)])
        : null;
    securityPending = true;
    final Map<String, dynamic> staged;
    try {
      staged = await _active.run('security-stage', [
        jsonEncode(changes),
        expected ?? plan!['digest'] as String,
      ]);
    } catch (_) {
      await _securityStatus();
      rethrow;
    }
    final token = staged['token'] as String;
    try {
      final fresh = await _connectUsing(_login, (_, _) async => false);
      final check = backendFactory(fresh, _login.user);
      try {
        await check.run('preflight');
        final confirmed = await check.run('security-confirm', [token]);
        if (confirmed['confirmed'] != true) {
          throw StateError('Security confirmation failed.');
        }
      } finally {
        await check.close();
        await fresh.close();
      }
    } catch (_) {
      try {
        await _active.run('security-rollback', [token]);
      } catch (_) {
        /* Server timer retains recovery. */
      }
      await _securityStatus();
      rethrow;
    }
    await _securityStatus();
  }

  Future<bool> applySecurity(Map<String, bool> changes, String digest) =>
      _guard(() async {
        tasks = [
          SetupTask('Verify access, apply and confirm security settings'),
          SetupTask('Refresh diagnostics'),
        ];
        tasks[0].state = TaskState.running;
        _notify();
        try {
          await _securityApply(changes, expected: digest);
          tasks[0].state = TaskState.done;
        } catch (_) {
          tasks[0].state = TaskState.failed;
          rethrow;
        }
        tasks[1].state = TaskState.running;
        _notify();
        await _refresh();
        tasks[1].state = TaskState.done;
        message = 'Security settings confirmed through a new SSH connection.';
      });

  Future<bool> unbanAddress(String address) => _guard(() async {
    await _active.run('security-unban', [address]);
    await _securityStatus();
    message = 'Address removed from the Ashapp SSH jail.';
  });

  Future<void> _installIdentity(String pem, String passphrase) async {
    final identity = SshIdentity.parse(pem, passphrase);
    _secrets.addAll([pem, passphrase]);
    await _active.run('ssh-key', [_login.user, identity.publicKey]);
    final candidate = ConnectionDetails(
      host: _login.host,
      port: _login.port,
      user: _login.user,
      password: _login.password,
      privateKey: pem,
      keyPassphrase: passphrase,
    );
    final fresh = await _connectUsing(candidate, (_, _) async => false);
    final backend = backendFactory(fresh, candidate.user);
    try {
      await backend.run('preflight');
      // A recoverable key must be saved before a password-denial operation.
      await vault.saveConnection(candidate);
    } catch (_) {
      await backend.close();
      await fresh.close();
      rethrow;
    }
    final old = _active;
    await socksTunnel?.close();
    socksTunnel = null;
    socks = null;
    await _output?.cancel();
    _backend = backend;
    ssh = candidate;
    remember = true;
    _output = backend.output.stream.listen(_append);
    _watchConnection(backend);
    await old.close();
    await old.connection.close();
  }

  Future<bool> installSshIdentity(
    String pem,
    String passphrase, {
    bool generate = false,
  }) => _guard(() async {
    final identity = generate
        ? SshIdentity.generate()
        : SshIdentity.parse(pem, passphrase);
    await _installIdentity(identity.privateKey, generate ? '' : passphrase);
    message = 'SSH key saved in the OS vault; independent key login and sudo verified.';
  });

  Future<bool> refresh() => _guard(() async {
    await _refresh();
    message = 'Server status updated.';
  });

  Future<void> _administrator(String name, String password) async {
    if (!SetupSecrets.usernameValid(name) ||
        !SetupSecrets.passwordValid(password)) {
      throw StateError(
        'Enter a valid administrator name and an 8-character password.',
      );
    }
    _secrets.add(password);
    final old = _active;
    final details = _login;
    await old.run('create-user', [name, password]);
    final changed = ConnectionDetails(
      host: details.host,
      port: details.port,
      user: name,
      password: password,
      privateKey: details.privateKey,
      keyPassphrase: details.keyPassphrase,
    );
    savedAccount = changed;
    if (details.user == name) ssh = changed;
    // The password has already changed remotely, even if later verification fails.
    await _rememberLogin(additional: changed);
    await old.run('ssh-config', [name, 'keep']);
    if (details.usesKey) {
      final identity = SshIdentity.parse(
        details.privateKey,
        details.keyPassphrase,
      );
      await old.run('ssh-key', [name, identity.publicKey]);
    }
    final checked = await _connectUsing(changed, (_, _) async => false);
    final backend = backendFactory(checked, name);
    try {
      await backend.run('preflight'); // Includes actual sudo -n verification.
      if (_disposed) throw StateError('The app was closed.');
    } catch (_) {
      await backend.close();
      await checked.close();
      rethrow;
    }
    // Adopt the verified login without clearing setup progress or service results.
    await socksTunnel?.close();
    socksTunnel = null;
    socks = null;
    await _output?.cancel();
    _backend = backend;
    ssh = changed;
    _output = backend.output.stream.listen(_append);
    _watchConnection(backend);
    await old.close();
    await old.connection.close();
    await _rememberLogin();
    _append('New administrator SSH login and passwordless sudo verified.');
  }

  Future<bool> createAdministrator(String name, String password) =>
      _guard(() async {
        await _active.run('dependencies');
        await _administrator(name, password);
        await _refresh();
        message = 'Administrator created and connected.';
      });
  Future<void> _disableRoot() async {
    final details = _login;
    if (details.user == 'root') {
      throw StateError(
        'Use a verified administrator before disabling root SSH.',
      );
    }
    await _securityApply({'disable_root': true});
  }

  Future<bool> disableRoot() => _guard(() async {
    await _disableRoot();
    await _refresh();
    message = 'Root SSH login disabled.';
  });
  Future<void> _rootPassword(String password) async {
    if (!SetupSecrets.passwordValid(password)) {
      throw StateError('Use a password with at least 8 characters.');
    }
    _secrets.add(password);
    await _active.run('root-password', [password]);
    final details = _login;
    final root = ConnectionDetails(
      host: details.host,
      port: details.port,
      user: 'root',
      password: password,
    );
    savedAccount = root;
    if (details.user == 'root') {
      ssh = ConnectionDetails(
        host: details.host,
        port: details.port,
        user: 'root',
        password: password,
        privateKey: details.privateKey,
        keyPassphrase: details.keyPassphrase,
      );
    }
    await _rememberLogin(additional: root);
  }

  Future<bool> changeRootPassword(String password) => _guard(() async {
    await _rootPassword(password);
    message = 'Root password changed.';
  });

  Future<bool> readSavedAccount(String user) => _guard(() async {
    final details = _login;
    final saved = await vault.account(details.host, details.port, user);
    if (saved == null) {
      throw StateError(
        'No credentials for this account are saved on this device.',
      );
    }
    savedAccount = saved;
    _secrets.add(saved.password);
    message = 'Saved account credentials loaded.';
  });

  bool get managesFirewall =>
      (security?['firewall'] as Map?)?['managed'] == true;
  bool _activatesService(ServerTemplate answers) =>
      (answers.installAwg && server['awg_configured'] != true) ||
      (answers.installVless &&
          (server['vless_configured'] != true || server['vless'] != true)) ||
      (answers.installSocks &&
          (server['socks5_configured'] != true || server['socks5'] != true));
  bool needsFirewallRefresh(ServerTemplate answers) =>
      managesFirewall && _activatesService(answers);

  Future<bool> provision(
    ServerTemplate answers,
    SetupSecrets secrets,
  ) => _guard(() async {
    final validation = secrets.validate(answers, activeUser: _login.user);
    if (validation != null) throw StateError(validation);
    if (!answers.generateSshKey && secrets.sshPrivateKey.isNotEmpty) {
      SshIdentity.parse(secrets.sshPrivateKey, secrets.sshKeyPassphrase);
    }
    _secrets.addAll([
      secrets.rootPassword,
      secrets.adminPassword,
      secrets.socksPassword,
    ]);
    setupComplete = false;
    final work = <(String, Future<void> Function())>[
      (
        'Install base packages',
        () async {
          await _active.run('dependencies');
        },
      ),
      if (answers.upgradePackages)
        (
          'Update system packages',
          () async {
            await _active.run('upgrade');
          },
        ),
      // Detect a required reboot before changing accounts or installing services.
      (
        'Inspect server',
        () async {
          server = await _active.run('status');
          await _securityStatus();
          if (_activatesService(answers) && security == null) {
            throw StateError(
              'Security diagnostics must succeed before adding a network service.',
            );
          }
          if (needsFirewallRefresh(answers) && !answers.configureFirewall) {
            throw StateError(
              'Select Configure firewall to review and refresh the existing Ashapp allowlist for the new service.',
            );
          }
          if (answers.installSocks &&
              server['vless_configured'] == true &&
              server['vless_port'] == answers.socksPort) {
            throw StateError(
              'The selected SOCKS5 port is reserved by VLESS. Choose another TCP port.',
            );
          }
          if (answers.installVless &&
              server['vless_configured'] != true &&
              server['socks5_configured'] == true &&
              server['socks5_port'] == answers.vlessPort) {
            throw StateError(
              'The selected VLESS port is reserved by SOCKS5. Choose another TCP port.',
            );
          }
          if (answers.installAwg &&
              ((server['external_awg'] as List? ?? []).isNotEmpty ||
                  server['vpn_detection_error'] != null)) {
            throw StateError(
              'An existing AmneziaVPN deployment was found or VPN discovery failed. Refresh and manage the existing VPN; setup will not replace it.',
            );
          }
          if (answers.installAwg &&
              server['reboot_required'] == true &&
              server['awg_configured'] != true) {
            throw StateError(
              'The server needs a reboot. Reboot it, reconnect, then run setup again.',
            );
          }
          if (answers.protectSsh ||
              answers.configureFirewall ||
              answers.automaticUpdates ||
              answers.disablePasswordLogin ||
              answers.disableRoot) {
            await _active.run('security-preview', [
              jsonEncode({
                if (answers.protectSsh) 'fail2ban': true,
                if (answers.configureFirewall) 'firewall': true,
                if (answers.automaticUpdates) 'automatic_updates': true,
                if (answers.disablePasswordLogin) 'disable_passwords': true,
                if (answers.disableRoot) 'disable_root': true,
              }),
            ]);
          }
        },
      ),
      if (answers.changeRootPassword)
        ('Change root password', () => _rootPassword(secrets.rootPassword)),
      if (answers.createAdmin)
        (
          'Create and verify administrator',
          () => _administrator(secrets.adminName, secrets.adminPassword),
        ),
      if (secrets.sshPublicKey.isNotEmpty)
        (
          'Install optional SSH key',
          () async {
            await _active.run('ssh-key', [_login.user, secrets.sshPublicKey]);
          },
        ),
      if (answers.generateSshKey || secrets.sshPrivateKey.isNotEmpty)
        (
          'Install and verify SSH key',
          () async {
            final pem = answers.generateSshKey
                ? SshIdentity.generate().privateKey
                : secrets.sshPrivateKey;
            await _installIdentity(
              pem,
              answers.generateSshKey ? '' : secrets.sshKeyPassphrase,
            );
          },
        ),
      if (answers.disableRoot) ('Disable root SSH login', _disableRoot),
      if (answers.blockPing)
        (
          'Block ping replies',
          () async {
            await _active.run('icmp');
          },
        ),
      if (answers.installAwg)
        (
          'Install AmneziaWG kernel',
          () async {
            final inspected = await _active.run('status');
            if (inspected['awg_configured'] == true) {
              if (inspected['awg'] != true ||
                  inspected['kernel'] != true ||
                  inspected['userspace'] == true) {
                throw StateError(
                  'An existing VPN configuration needs attention. Use service controls; setup will not overwrite it.',
                );
              }
              _append(
                'Preserving the existing kernel VPN and its port/DNS settings.',
              );
            } else {
              await _active.run('prepare-awg');
              await _active.run('install-awg-configured', [
                _login.host,
                '${answers.awgPort}',
                answers.awgDns,
              ]);
            }
            await _active.run('check-awg');
          },
        ),
      if (answers.installSocks)
        (
          'Install and verify SOCKS5',
          () async {
            final inspected = await _active.run('status');
            if (inspected['socks5_configured'] == true ||
                inspected['socks5'] == true) {
              _append('Preserving the existing SOCKS5 credentials and port.');
              if (inspected['socks5'] != true) {
                await _active.run('socks-control', ['start']);
              }
            } else {
              await _active.run('socks-install', [
                '${answers.socksPort}',
                secrets.socksUser,
                secrets.socksPassword,
                'no',
                answers.socksAccess,
              ]);
            }
            await _active.run('socks-check');
            await _readSocks();
          },
        ),
      if (answers.installVless)
        (
          'Install VLESS + Reality + XTLS Vision',
          () async {
            final result = await _active.run('install-vless', [
              _login.host,
              '${answers.vlessPort}',
              answers.realitySni,
              answers.realityFingerprint,
            ]);
            if (result['preserved'] == true) {
              _append(
                'Preserving the existing Ashapp VLESS settings, keys and clients.',
              );
            }
            if (result['vless'] != true) {
              await _active.run('vless-control', ['start']);
            }
          },
        ),
      if (answers.installAwg && answers.clientNames.isNotEmpty)
        (
          'Create requested VPN clients',
          () async {
            final result = await _active.run('clients');
            final names = (result['clients'] as List? ?? [])
                .where((c) => (c as Map)['source'] != VlessConnection.source)
                .map((c) => (c as Map)['name'])
                .toSet();
            for (final name in answers.clientNames) {
              if (!names.contains(name)) {
                await _active.run('add-client', [name]);
              }
            }
          },
        ),
      if (answers.installVless && answers.vlessClientNames.isNotEmpty)
        (
          'Create requested VLESS clients',
          () async {
            final result = await _active.run('clients');
            final names = (result['clients'] as List? ?? [])
                .where((c) => (c as Map)['source'] == VlessConnection.source)
                .map((c) => (c as Map)['name'])
                .toSet();
            for (final name in answers.vlessClientNames) {
              if (!names.contains(name)) {
                await _active.run('add-client', [name, VlessConnection.source]);
              }
            }
          },
        ),
      if (answers.protectSsh ||
          answers.configureFirewall ||
          answers.automaticUpdates ||
          answers.disablePasswordLogin)
        (
          'Apply and confirm security protection',
          () => _securityApply({
            if (answers.protectSsh) 'fail2ban': true,
            if (answers.configureFirewall) 'firewall': true,
            if (answers.automaticUpdates) 'automatic_updates': true,
            if (answers.disablePasswordLogin) 'disable_passwords': true,
          }),
        ),
      (
        'Verify final configuration',
        () async {
          await _refresh();
          if (answers.installAwg &&
              (server['awg'] != true ||
                  server['kernel'] != true ||
                  server['userspace'] == true)) {
            throw StateError('Kernel VPN verification did not pass.');
          }
          if (answers.installSocks && server['socks5'] != true) {
            throw StateError('SOCKS5 is not running.');
          }
          if (answers.installVless && server['vless'] != true) {
            throw StateError(
              'VLESS sing-box service verification did not pass.',
            );
          }
          if (answers.blockPing && server['icmp_blocked'] != true) {
            throw StateError('Ping blocking was not confirmed.');
          }
          if (answers.disableRoot &&
              (server['ssh'] as Map?)?['permitrootlogin'] != 'no') {
            throw StateError('Root SSH login is not disabled.');
          }
        },
      ),
    ];
    tasks = work.map((item) => SetupTask(item.$1)).toList();
    _notify();
    for (var i = 0; i < work.length; i++) {
      final task = tasks[i];
      task.state = TaskState.running;
      message = task.label;
      _notify();
      try {
        await work[i].$2();
        task.state = TaskState.done;
      } catch (_) {
        task.state = TaskState.failed;
        rethrow;
      }
      _notify();
    }
    setupComplete = true;
    message = answers.installAwg || answers.installVless
        ? 'Server setup complete.'
        : 'Server prepared. You can install VPN later.';
  });

  List<String> get clientSources => [
    if (server['vless_configured'] == true && server['vless_error'] == null)
      VlessConnection.source,
    if (server['awg'] == true &&
        server['kernel'] == true &&
        server['interface'] is String)
      server['interface'] as String,
    for (final item in server['external_awg'] as List? ?? [])
      if (item['running'] == true) item['source'] as String,
  ];

  bool _externalSource(String? source) =>
      {'amnezia-awg', 'amnezia-awg2'}.contains(source);
  bool _clientNameValid(String name, String? source) =>
      (_externalSource(source) || source == VlessConnection.source)
      ? name.trim() == name &&
            name.isNotEmpty &&
            name.runes.length <= 64 &&
            !RegExp(r'[\x00-\x1f\x7f]').hasMatch(name)
      : RegExp(r'^[A-Za-z0-9_-]{1,15}$').hasMatch(name);

  Future<bool> addClient(
    String name, {
    String? source,
    String dns = '1.1.1.1',
  }) => _guard(() async {
    if (!_clientNameValid(name, source)) {
      throw StateError(
        (_externalSource(source) || source == VlessConnection.source)
            ? 'Use a client name of 1–64 characters without control characters.'
            : 'Use up to 15 letters, numbers, underscores or hyphens.',
      );
    }
    if (source != null && !clientSources.contains(source)) {
      throw StateError('The selected VPN is unavailable. Refresh first.');
    }
    final result = await _active.run('add-client', [
      name,
      ?source,
      if (_externalSource(source)) ...[_login.host, dns],
    ]);
    await _refresh();
    message = source == VlessConnection.source
        ? 'VLESS client $name created. VLESS connections may briefly reconnect.'
        : 'Client $name created.';
    if (result['warning'] case final String warning) {
      message += ' $warning';
      _append(warning);
    }
  });
  Future<bool> revokeClient(String name, {String? source, String? publicKey}) =>
      _guard(() async {
        final result = await _active.run('revoke-client', [
          name,
          if (source != null) ...[source, publicKey ?? ''],
        ]);
        await _refresh();
        message = 'Client $name revoked.';
        if (result['warning'] case final String warning) {
          message += ' $warning';
          _append(warning);
        }
      });
  Future<bool> renameClient(
    String name,
    String replacement, {
    required String source,
    required String publicKey,
  }) => _guard(() async {
    if (!_clientNameValid(replacement, source)) {
      throw StateError('Enter a valid client name.');
    }
    final result = await _active.run('rename-client', [
      name,
      source,
      publicKey,
      replacement,
    ]);
    await _refresh();
    message = 'Client renamed to $replacement.';
    if (result['warning'] case final String warning) {
      message += ' $warning';
      _append(warning);
    }
  });
  Future<String?> clientConfig(
    String name, {
    String? source,
    String? publicKey,
  }) async {
    String? config;
    await _guard(() async {
      final response = await _active.run('get-client', [
        name,
        if (source != null) ...[source, publicKey ?? ''],
      ]);
      if (response['config'] is! String) {
        throw const FormatException('The client configuration is unavailable.');
      }
      config = response['config'] as String;
      _secrets.addAll(ClientConfiguration(config!).secrets);
    });
    return config;
  }

  Future<VlessConnection?> vlessConnection(String name, String identity) async {
    VlessConnection? connection;
    await _guard(() async {
      final response = await _active.run('get-client', [
        name,
        VlessConnection.source,
        identity,
      ]);
      final value = response['connection'];
      if (value is! Map<String, dynamic>) {
        throw const FormatException('VLESS connection is unavailable.');
      }
      final parsed = VlessConnection.fromJson(value);
      if (parsed.uuid != identity) {
        throw const FormatException('VLESS identity changed. Refresh first.');
      }
      _secrets.addAll([parsed.uuid, parsed.publicKey, parsed.shortId]);
      connection = parsed;
    });
    return connection;
  }

  Future<bool> importClientConfiguration(
    String name,
    String content, {
    required String source,
    required String publicKey,
    bool replace = false,
  }) => _guard(() async {
    final config = ClientConfiguration(content);
    if (!config.withinLimit || config.privateKey == null) {
      throw StateError(
        'Import a full client .conf with its original private key, up to 128 KiB.',
      );
    }
    _secrets.addAll(config.secrets);
    await _active.run('import-client', [
      name,
      source,
      publicKey,
      content,
      replace ? 'yes' : 'no',
    ]);
    await _refresh();
    message = 'Existing configuration saved. Its key and VPN access were not changed.';
  });

  Future<void> _readSocks() async {
    final result = await _active.run('socks-info');
    socks = ConnectionDetails(
      host: result['access'] == 'private' ? '127.0.0.1' : _login.host,
      port: result['access'] == 'private' && socksTunnel != null
          ? socksTunnel!.port
          : result['port'] as int,
      user: result['user'] as String,
      password: result['password'] as String,
    );
    _secrets.add(socks!.password);
    server['socks5_access'] = result['access'] ?? 'public';
  }

  Future<bool> startSocksTunnel() => _guard(() async {
    await socksTunnel?.close();
    socksTunnel = null;
    await _readSocks();
    if (server['socks5_access'] != 'private') {
      throw StateError('Select private SOCKS5 access first.');
    }
    socksTunnel = await SocksTunnel.start(
      _active.connection.client,
      socks!.port,
    );
    socks = ConnectionDetails(
      host: '127.0.0.1',
      port: socksTunnel!.port,
      user: socks!.user,
      password: socks!.password,
    );
    message =
        'Private SOCKS5 tunnel is running on 127.0.0.1:${socksTunnel!.port}. Keep Ashapp connected.';
  });
  Future<bool> stopSocksTunnel() => _guard(() async {
    await socksTunnel?.close();
    socksTunnel = null;
    socks = null;
    message = 'Private SOCKS5 tunnel stopped.';
  });

  Future<bool> readSocks() => _guard(_readSocks);
  Future<bool> configureSocks(
    int port,
    String user,
    String password, {
    bool replace = false,
    String access = 'public',
  }) => _guard(() async {
    if (!{'public', 'private'}.contains(access) ||
        port < 1 ||
        port > 65535 ||
        port == _login.port ||
        (server['vless_configured'] == true && server['vless_port'] == port) ||
        !RegExp(r'^[A-Za-z0-9_]{1,128}$').hasMatch(user) ||
        !RegExp(r'^[A-Za-z0-9_]{8,128}$').hasMatch(password)) {
      throw StateError(
        'Check the SOCKS5 credentials and use a TCP port different from SSH and VLESS.',
      );
    }
    _secrets.add(password);
    await socksTunnel?.close();
    socksTunnel = null;
    await _active.run('dependencies');
    await _active.run('socks-install', [
      '$port',
      user,
      password,
      replace ? 'yes' : 'no',
      access,
    ]);
    await _active.run('socks-check');
    await _readSocks();
    await _refresh();
    if ((security?['firewall'] as Map?)?['managed'] == true) {
      await _securityApply({'firewall': true});
    }
    message = 'SOCKS5 credentials verified.';
  });
  Future<bool> service(String kind, String operation) => _guard(() async {
    if (!{'awg', 'socks', 'vless'}.contains(kind) ||
        !{'start', 'stop', 'restart'}.contains(operation)) {
      throw StateError('Invalid service command.');
    }
    await _active.run('$kind-control', [operation]);
    if (operation != 'stop' && managesFirewall) {
      await _securityApply({'firewall': true});
    }
    await _refresh();
    message = 'Service $operation completed.';
  });
  Future<bool> blockPing(bool block) => _guard(() async {
    await _active.run('dependencies');
    await _active.run(block ? 'icmp' : 'icmp-unblock');
    await _refresh();
    message = block ? 'Ping replies blocked.' : 'Ashapp ping block removed.';
  });
  Future<bool> reboot() => _guard(() async {
    await _active.run('reboot');
    message = 'Reboot scheduled. Reconnect after the server starts.';
  });

  @override
  void dispose() {
    _disposed = true;
    unawaited(socksTunnel?.close());
    socksTunnel = null;
    _progressTimer?.cancel();
    _output?.cancel();
    final old = _backend;
    _backend = null;
    if (old != null) unawaited(old.close().whenComplete(old.connection.close));
    _secrets.clear();
    super.dispose();
  }
}
