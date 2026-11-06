import 'dart:async';
import 'dart:math';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import 'connection_details.dart';
import 'client_configuration.dart';
import 'credential_vault.dart';
import 'remote_backend.dart';
import 'server_profiles.dart';
import 'server_template.dart';
import 'setup_secrets.dart';
import 'ssh_connection.dart';
import 'host_key_store.dart';
import 'ssh_failure.dart';
import 'template_repository.dart';
import 'vless_connection.dart';
import 'ssh_identity.dart';
import 'socks_tunnel.dart';
import 'provisioning_state.dart';

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
  HostKeyChange? changedHostKey;
  Map<String, dynamic> server = {};
  Map<String, dynamic> operatingSystem = {};
  Map<String, dynamic> installation = {};
  List<Map<String, dynamic>> diagnosticChecks = [];
  final List<String> inspectionWarnings = [];
  ProvisioningDraft? _setupDraft;
  bool get canResumeSetup =>
      {'failed', 'running'}.contains(installation['status']) &&
      installation['run_id'] is String;
  Future<ProvisioningDraft?> recoveryDraft() async {
    final login = _login;
    final draft = _setupDraft ?? await vault.setup(login.host, login.port);
    return draft?.runId == installation['run_id'] ? draft : null;
  }

  Map<String, dynamic>? security;
  String securityError = '';
  bool securityPending = false;
  SocksTunnel? socksTunnel;
  ({String? containerId, String? source, int port})? _socksReadTarget,
      _socksTunnelTarget;
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
    String plain(String value) => value
        .replaceAll(RegExp(r'\x1B\[[0-?]*[ -/]*[@-~]'), '')
        .replaceAll(RegExp(r'[\x00-\x08\x0B-\x1F\x7F]'), '');
    var safe = line;
    final secrets =
        _secrets
            .expand(
              (s) => [
                s,
                plain(s),
                if (s.contains('\n'))
                  for (final part in const LineSplitter().convert(s)) ...[
                    part,
                    plain(part),
                  ],
              ],
            )
            .where((s) => s.isNotEmpty)
            .toSet()
            .toList()
          ..sort((a, b) => b.length.compareTo(a.length));
    for (final secret in secrets) {
      safe = safe.replaceAll(secret, '********');
    }
    safe = plain(safe);
    // An upstream transport may already have removed only some controls.
    // Redact again after full normalization so partial variants cannot leak.
    for (final secret in secrets) {
      safe = safe.replaceAll(secret, '********');
    }
    safe = safe.replaceAll(
      RegExp(r'\bvpn://[A-Za-z0-9_+/=\-]+', caseSensitive: false),
      'vpn://********',
    );
    safe = safe.replaceAllMapped(
      RegExp(
        r'((?:PrivateKey|PresharedKey|password|secret)\s*[=:]\s*)[^\s,;]+',
        caseSensitive: false,
      ),
      (match) => '${match[1]}********',
    );
    return safe.replaceAll(
      RegExp(
        r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        caseSensitive: false,
      ),
      '********',
    );
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
    diagnosticChecks = [];
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
    if (connected && ssh?.host == profile.ip && ssh?.port == profile.sshPort) {
      throw StateError('Disconnect this server before forgetting it.');
    }
    final known = KnownHosts(
      File.fromUri(
        profilesRepository.file.parent.uri.resolve('known_hosts.json'),
      ),
    );
    await known.forget('${profile.ip}:${profile.sshPort}');
    await vault.forgetSetup(profile.ip, profile.sshPort);
    await vault.forgetConnection(profile.ip, profile.sshPort);
    await profilesRepository.remove(profile);
    profiles = await profilesRepository.load();
    message = 'Removed from this device. The server was not changed.';
  });
  Future<bool> forgetPassword() => _guard(() async {
    final details = _login;
    await vault.forgetSetup(details.host, details.port);
    await vault.forgetConnection(details.host, details.port);
    remember = false;
    message = 'Saved SSH credentials removed. The current session stays open.';
  });

  Future<bool> acceptChangedHostKey(HostKeyChange change) => _guard(() async {
    if (!identical(change, changedHostKey)) {
      throw StateError(
        'This server-key review is no longer current. Reconnect first.',
      );
    }
    final known = KnownHosts(
      File.fromUri(
        profilesRepository.file.parent.uri.resolve('known_hosts.json'),
      ),
    );
    if (!await known.acceptChange(change)) {
      throw StateError(
        'The saved server key changed during review. Reconnect and review it again.',
      );
    }
    changedHostKey = null;
    message =
        'Server key updated. Connect again using the current SSH credentials.';
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
        log = '';
        changedHostKey = null;
        _secrets.addAll([
          details.password,
          details.privateKey,
          details.keyPassphrase,
        ]);
        message = 'Connecting…';
        _append('[SSH] Connecting to ${details.host}:${details.port}.');
        _notify();
        late final SshConnection next;
        try {
          next = await _connectUsing(details, confirmHost);
        } catch (error) {
          if (error is HostKeyChange) changedHostKey = error;
          final failure = sshFailureMessage(error);
          _append('[SSH] $failure');
          throw StateError(failure);
        }
        final backend = backendFactory(next, details.user);
        final preparingOutput = backend.output.stream.listen(_append);
        try {
          final preflight = await backend.run('preflight');
          if (_disposed) throw StateError('The app was closed.');
          unawaited(preparingOutput.cancel());
          await _adopt(backend, details, preserveLog: true);
          operatingSystem = Map<String, dynamic>.of(preflight);
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
          unawaited(preparingOutput.cancel());
          if (!identical(_backend, backend)) {
            await backend.close();
            await next.close();
          }
          rethrow;
        }
      });

  Future<void> _adopt(
    RemoteBackend next,
    ConnectionDetails details, {
    bool preserveLog = false,
  }) async {
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
    operatingSystem = {};
    installation = {};
    diagnosticChecks = [];
    inspectionWarnings.clear();
    _setupDraft = null;
    security = null;
    securityPending = false;
    setupComplete = false;
    tasks = [];
    if (!preserveLog) log = '';
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
        await vault.forgetSetup(details.host, details.port);
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
      installation = {};
      diagnosticChecks = [];
      inspectionWarnings.clear();
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
    operatingSystem = {};
    installation = {};
    diagnosticChecks = [];
    inspectionWarnings.clear();
    _setupDraft = null;
    security = null;
    log = '';
    tasks = [];
    _secrets.clear();
    setupComplete = false;
    message = 'Disconnected.';
  });

  Future<void> _refresh() async {
    inspectionWarnings.clear();
    // Loaded proxy credentials are an explicit read, not status evidence. The
    // other manager may change them without changing this container's ports.
    socks = null;
    _socksReadTarget = null;
    server = {};
    try {
      server = await _active.run('status');
    } catch (_) {
      inspectionWarnings.add(
        'Server inspection failed. Protocol state is unknown; open Server activity for details.',
      );
    }
    await _reconcileSocksStatus(server);
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
    users = [];
    try {
      final result = await _active.run('users');
      users = List<Map<String, dynamic>>.from(result['users'] as List? ?? []);
    } catch (_) {
      inspectionWarnings.add('Administrator list could not be inspected.');
    }
    await _securityStatus();
    await _installationStatus();
  }

  Future<void> _installationStatus() async {
    installation = {};
    try {
      installation = await _active.run('lifecycle-status');
    } catch (_) {
      inspectionWarnings.add(
        'The server installation journal could not be read. Completed work has not been changed.',
      );
    }
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
    await _diagnose();
  });

  Future<Map<String, dynamic>?> previewReset() async {
    Map<String, dynamic>? result;
    await _guard(() async {
      result = {
        'endpoint': '${_login.host}:${_login.port}',
        'security': await _active.run('security-reset-preview'),
        'components': await _active.run('reset-preview'),
      };
    });
    return result;
  }

  /// Restores owned policy through the same timed SSH recovery boundary.
  Future<bool> resetServer(Map<String, dynamic> reviewed) => _guard(() async {
    if (reviewed['endpoint'] != '${_login.host}:${_login.port}') {
      throw StateError('This reset review belongs to another server.');
    }
    final componentPlan = reviewed['components'] as Map;
    final freshPlan = await _active.run('reset-preview');
    if (freshPlan['digest'] != componentPlan['digest']) {
      throw StateError(
        'The server changed after the reset review. Review it again.',
      );
    }
    final proof = await _connectUsing(_login, (_, _) async => false);
    final proofBackend = backendFactory(proof, _login.user);
    try {
      await proofBackend.run('preflight');
    } finally {
      await proofBackend.close();
      await proof.close();
    }
    final policy = reviewed['security'] as Map;
    if (policy['available'] == true) {
      securityPending = true;
      try {
        final staged = await _active.run('security-reset-stage', [
          policy['digest'] as String,
        ]);
        await _confirmStagedSecurity(staged);
      } catch (_) {
        await _securityStatus();
        rethrow;
      }
    }
    await socksTunnel?.close();
    socksTunnel = null;
    socks = null;
    final result = await _active.run('reset', [
      componentPlan['digest'] as String,
    ]);
    for (final warning in result['warnings'] as List? ?? []) {
      _append('[RESET] ${warning.toString()}');
    }
    setupComplete = false;
    _setupDraft = null;
    await vault.forgetSetup(_login.host, _login.port);
    await _refresh();
    diagnosticChecks = [];
    message = 'Reviewed components reset. Preserved or unverified installations remain. Accounts, passwords and system packages are unchanged.';
  });

  Future<void> _diagnose() async {
    message = 'Checking the actual server configuration…';
    diagnosticChecks = [];
    socks = null;
    _socksReadTarget = null;
    final Map<String, dynamic> result;
    try {
      result = await _active.run('diagnostics');
    } catch (_) {
      await _reconcileSocksStatus(const {});
      rethrow;
    }
    diagnosticChecks = List<Map<String, dynamic>>.from(
      result['checks'] as List? ?? [],
    );
    if (diagnosticChecks.isEmpty) {
      await _reconcileSocksStatus(const {});
      throw StateError(
        'Diagnostics returned no checks. The server has not been marked ready.',
      );
    }
    final actual = result['actual'] as Map?;
    if (actual?['server'] is Map) {
      server = Map<String, dynamic>.from(actual!['server'] as Map);
    }
    await _reconcileSocksStatus(
      actual?['server'] is Map
          ? Map<String, dynamic>.from(actual!['server'] as Map)
          : const {},
    );
    if (actual?['security'] is Map) {
      security = Map<String, dynamic>.from(actual!['security'] as Map);
      securityError = '';
      securityPending = security?['pending'] == true;
    }
    if (result['lifecycle'] is Map) {
      installation = Map<String, dynamic>.from(result['lifecycle'] as Map);
    }
    final failed = diagnosticChecks
        .where(
          (c) =>
              c['required'] != false &&
              (c['status'] == 'fail' || c['status'] == 'unknown'),
        )
        .length;
    setupComplete = installation['status'] == 'complete' && failed == 0;
    message = failed == 0
        ? 'Diagnostics completed. Review warnings and external connectivity limits below.'
        : 'Diagnostics found $failed failed or unknown checks.';
  }

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
    securityPending = true;
    final Map<String, dynamic> staged;
    try {
      staged = await _active.run(
        expected == null ? 'security-setup' : 'security-stage',
        [jsonEncode(changes), ?expected],
      );
    } catch (_) {
      await _securityStatus();
      rethrow;
    }
    await _confirmStagedSecurity(staged);
  }

  Future<void> _confirmStagedSecurity(Map<String, dynamic> staged) async {
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

  Future<void> _administrator(
    String name,
    String password, {
    bool writePassword = true,
  }) async {
    if (!SetupSecrets.usernameValid(name) ||
        !SetupSecrets.passwordValid(password)) {
      throw StateError(
        'Enter a valid administrator name and an 8-character password.',
      );
    }
    _secrets.add(password);
    final old = _active;
    final details = _login;
    if (writePassword) await old.run('create-user', [name, password]);
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
    if (writePassword) await _rememberLogin(additional: changed);
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
  Future<void> _rootPassword(
    String password, {
    bool writePassword = true,
  }) async {
    if (!SetupSecrets.passwordValid(password)) {
      throw StateError('Use a password with at least 8 characters.');
    }
    _secrets.add(password);
    if (writePassword) await _active.run('root-password', [password]);
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
      (answers.installAwg &&
          (server['awg_configured'] != true || server['awg'] != true)) ||
      (answers.installVless &&
          (server['vless_configured'] != true || server['vless'] != true)) ||
      (answers.installSocks &&
          (server['socks5_configured'] != true || server['socks5'] != true));
  bool needsFirewallRefresh(ServerTemplate answers) =>
      managesFirewall && _activatesService(answers);

  Map<String, bool> _setupSecurityChoices(ServerTemplate answers) {
    final features = security?['managed_features'] as List? ?? const [];
    return {
      if (answers.protectSsh ||
          (security?['fail2ban'] as Map?)?['managed'] == true)
        'fail2ban': answers.protectSsh,
      if (answers.configureFirewall || managesFirewall)
        'firewall': answers.configureFirewall,
      if (answers.automaticUpdates ||
          (security?['automatic_updates'] as Map?)?['managed'] == true)
        'automatic_updates': answers.automaticUpdates,
      if (answers.disablePasswordLogin || features.contains('ssh'))
        'disable_passwords': answers.disablePasswordLogin,
      if (!answers.disableRoot && features.contains('ssh'))
        'disable_root': false,
    };
  }

  Future<bool> provision(
    ServerTemplate answers,
    SetupSecrets secrets, {
    String? resumeRunId,
  }) => _guard(() async {
    final validation = secrets.validate(
      answers,
      activeUser: _login.user,
      activeUsesKey: _login.usesKey,
      existingSocks: server['socks5_configured'] == true,
    );
    if (validation != null) throw StateError(validation);
    if (!answers.generateSshKey && secrets.sshPrivateKey.isNotEmpty) {
      SshIdentity.parse(secrets.sshPrivateKey, secrets.sshKeyPassphrase);
    }
    _secrets.addAll([
      secrets.rootPassword,
      secrets.adminPassword,
      secrets.socksPassword,
      secrets.sshPrivateKey,
      secrets.sshKeyPassphrase,
    ]);
    setupComplete = false;
    var resumeSteps = resumeRunId == null
        ? const <String, dynamic>{}
        : Map<String, dynamic>.from(
            (installation['steps'] as Map?) ?? const {},
          );
    final work = <(String, String, Future<void> Function())>[
      (
        'dependencies',
        'Install base packages',
        () async {
          await _active.run('dependencies');
        },
      ),
      if (answers.upgradePackages)
        (
          'upgrade',
          'Update system packages',
          () async {
            await _active.run('upgrade');
          },
        ),
      // Detect a required reboot before changing accounts or installing services.
      (
        'inspect',
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
          final externalAwg = server['external_awg'] as List? ?? [];
          final sharedAwg = answers.awgDeployment == 'amnezia';
          if (answers.installAwg &&
              sharedAwg &&
              server['architecture'] is String &&
              !{'x86_64', 'amd64'}.contains(server['architecture'])) {
            throw StateError(
              'Shared AmneziaVPN setup currently requires a Linux x86_64 VPS. Choose Host kernel for another supported architecture.',
            );
          }
          if (answers.installAwg &&
              (server['vpn_detection_error'] != null ||
                  (sharedAwg
                      ? server['awg_host_configured'] == true ||
                            (externalAwg.isNotEmpty &&
                                server['awg_deployment'] != 'amnezia')
                      : externalAwg.isNotEmpty))) {
            throw StateError(
              'A different VPN deployment was found or VPN discovery failed. Refresh and manage the existing VPN; setup will not replace or migrate it.',
            );
          }
          if (answers.installAwg &&
              server['reboot_required'] == true &&
              server['awg_configured'] != true) {
            throw StateError(
              'The server needs a reboot. Reboot it, reconnect, then run setup again.',
            );
          }
          final changes = _setupSecurityChoices(answers);
          if (changes.isNotEmpty || answers.disableRoot) {
            await _active.run('security-preview', [
              jsonEncode({
                ...changes,
                if (answers.disableRoot) 'disable_root': true,
              }),
            ]);
          }
        },
      ),
      if (answers.changeRootPassword)
        (
          'root-password',
          'Change root password',
          () => _rootPassword(
            secrets.rootPassword,
            writePassword:
                (resumeSteps['root-password'] as Map?)?['credential_state'] !=
                'committed',
          ),
        ),
      if (answers.createAdmin)
        (
          'administrator',
          'Create and verify administrator',
          () => _administrator(
            secrets.adminName,
            secrets.adminPassword,
            writePassword:
                (resumeSteps['administrator'] as Map?)?['credential_state'] !=
                'committed',
          ),
        ),
      if (secrets.sshPublicKey.isNotEmpty)
        (
          'ssh-public-key',
          'Install optional SSH key',
          () async {
            await _active.run('ssh-key', [_login.user, secrets.sshPublicKey]);
          },
        ),
      if (answers.generateSshKey || secrets.sshPrivateKey.isNotEmpty)
        (
          'ssh-key',
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
      if (answers.disableRoot)
        ('root-policy', 'Disable root SSH login', _disableRoot),
      if (answers.blockPing ||
          server['icmp_blocked'] == true ||
          resumeSteps.containsKey('ping'))
        (
          'ping',
          answers.blockPing ? 'Block ping replies' : 'Restore ping replies',
          () async {
            await _active.run(answers.blockPing ? 'icmp' : 'icmp-unblock');
          },
        ),
      if (answers.installAwg)
        (
          'awg',
          answers.awgDeployment == 'amnezia'
              ? 'Install shared AmneziaWG kernel'
              : 'Install AmneziaWG kernel',
          () async {
            final inspected = await _active.run('status');
            if (inspected['awg_configured'] == true) {
              if (inspected['userspace'] == true ||
                  (inspected['awg_deployment'] ?? 'host') !=
                      answers.awgDeployment) {
                throw StateError(
                  'An existing VPN configuration needs attention. Use service controls; setup will not overwrite it.',
                );
              }
              _append(
                'Preserving the existing kernel VPN and its port/DNS settings.',
              );
              if (inspected['awg'] != true) {
                await _active.run('awg-control', ['start']);
              }
            } else {
              await _active.run('prepare-awg');
              await _active.run(
                answers.awgDeployment == 'amnezia'
                    ? 'install-awg-amnezia'
                    : 'install-awg-configured',
                [_login.host, '${answers.awgPort}', answers.awgDns],
              );
            }
            await _active.run('check-awg');
          },
        ),
      if (answers.installSocks)
        (
          'socks',
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
          'vless',
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
          'awg-clients',
          'Create requested VPN clients',
          () async {
            final result = await _active.run('clients');
            final sharedAwg = answers.awgDeployment == 'amnezia';
            final selectedSource = sharedAwg
                ? 'amnezia-awg2'
                : server['interface'] as String? ?? 'awg0';
            final names = (result['clients'] as List? ?? [])
                .where(
                  (c) =>
                      (c as Map)['source'] == selectedSource ||
                      (!sharedAwg && c['source'] == null),
                )
                .map(
                  (c) => sharedAwg
                      ? ((c as Map)['name_key'] ??
                            c['name'].toString().toLowerCase())
                      : (c as Map)['name'],
                )
                .toSet();
            for (final name in answers.clientNames) {
              if (!names.contains(sharedAwg ? name.toLowerCase() : name)) {
                await _active.run(
                  'add-client',
                  sharedAwg
                      ? [name, selectedSource, _login.host, answers.awgDns]
                      : [name],
                );
              }
            }
          },
        ),
      if (answers.installVless && answers.vlessClientNames.isNotEmpty)
        (
          'vless-clients',
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
      for (final entry in {
        'awg': answers.installAwg,
        'socks': answers.installSocks,
        'vless': answers.installVless,
      }.entries)
        if (!entry.value &&
            (installation['owned_services'] as Map?)?[entry.key] == true &&
            server[entry.key == 'socks' ? 'socks5' : entry.key] == true)
          (
            '${entry.key}-stop',
            'Stop ${entry.key == 'socks' ? 'SOCKS5' : entry.key.toUpperCase()}',
            () async {
              if (entry.key == 'socks') {
                await socksTunnel?.close();
                socksTunnel = null;
                socks = null;
              }
              await _active.run('${entry.key}-control', ['stop']);
            },
          ),
      if (_setupSecurityChoices(answers).isNotEmpty ||
          resumeSteps.containsKey('security'))
        (
          'security',
          'Apply and confirm security protection',
          () async {
            final changes = _setupSecurityChoices(answers);
            if (changes.isNotEmpty) {
              await _securityApply(changes);
            } else {
              await _securityStatus();
            }
          },
        ),
      (
        'verify',
        'Verify final configuration',
        () async {
          await _refresh();
          if (answers.installAwg &&
              (server['awg'] != true ||
                  server['kernel'] != true ||
                  server['userspace'] == true ||
                  (server['awg_deployment'] ?? 'host') !=
                      answers.awgDeployment)) {
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
          await _diagnose();
          final failed = diagnosticChecks.where(
            (c) =>
                c['required'] != false &&
                (c['status'] == 'fail' || c['status'] == 'unknown'),
          );
          if (failed.isNotEmpty) {
            throw StateError(
              'Final diagnostics failed: ${failed.map((c) => c["id"]).join(", ")}. Review diagnostics before retrying.',
            );
          }
          if (answers.installSocks) await _readSocks();
        },
      ),
    ];
    if (resumeRunId != null) {
      final draft = await recoveryDraft();
      if (!canResumeSetup ||
          draft == null ||
          draft.runId != resumeRunId ||
          !draft.matches(answers, secrets)) {
        throw StateError(
          'Recovery answers changed or are unavailable. Open a new reviewed setup plan instead.',
        );
      }
      final recorded = (installation['steps'] as Map?) ?? const {};
      work.removeWhere((item) => !recorded.containsKey(item.$1));
      for (final id in recorded.keys.cast<String>()) {
        if (work.any((item) => item.$1 == id)) continue;
        if (!{'awg-stop', 'socks-stop', 'vless-stop'}.contains(id)) {
          throw StateError(
            'The saved setup plan is incompatible with this application. Review a new setup plan.',
          );
        }
        work.add((
          id,
          'Keep stopped ${id.split('-').first} service',
          () async {},
        ));
      }
    }
    if (operatingSystem['python'] == false) {
      await _active.run('dependencies');
      operatingSystem['python'] = true;
    }
    final intent = resumeRunId != null
        ? Map<String, Object>.from(installation['desired'] as Map)
        : {
            ...serverSetupIntent(answers),
            if (server['awg_configured'] == true && server['awg_port'] is int)
              'awg_port': server['awg_port'] as int,
            if (server['vless_configured'] == true &&
                server['vless_port'] is int)
              'vless_port': server['vless_port'] as int,
            if (server['vless_configured'] == true &&
                server['vless_sni'] is String)
              'reality_sni': server['vless_sni'] as String,
            if (server['socks5_configured'] == true &&
                server['socks5_port'] is int)
              'socks_port': server['socks5_port'] as int,
            if (server['socks5_configured'] == true &&
                server['socks5_access'] is String)
              'socks_access': server['socks5_access'] as String,
          };
    final started = await _active.run('lifecycle-begin', [
      jsonEncode({
        'desired': intent,
        'steps': work.map((item) => item.$1).toList(),
        'resume': resumeRunId != null,
        'run_id': ?resumeRunId,
      }),
    ]);
    final runId = started['run_id'];
    if (runId is! String || runId.isEmpty) {
      throw StateError(
        'The server could not save the setup journal. No setup steps were started.',
      );
    }
    installation = started;
    if (resumeRunId != null) {
      if (runId != resumeRunId || started['steps'] is! Map) {
        throw StateError(
          'The server returned a different recovery plan. No setup step was started.',
        );
      }
      // Only the freshly acknowledged server ledger authorizes credential
      // replay decisions. Failure reporting may have left the UI cache stale.
      resumeSteps = Map<String, dynamic>.from(started['steps'] as Map);
      for (final id in ['root-password', 'administrator']) {
        if ((resumeSteps[id] as Map?)?['credential_state'] == 'started' &&
            (resumeSteps[id] as Map?)?['state'] != 'done') {
          throw StateError(
            'A password write was interrupted before confirmation. Its current value is uncertain; resume will not change it again. Verify current access, then review a new setup plan if an explicit password change is needed.',
          );
        }
      }
      if ((resumeSteps['administrator'] as Map?)?['state'] == 'done' &&
          _login.user != secrets.adminName) {
        throw StateError(
          'Connect with the administrator already created by this setup before resuming. Its password will not be changed again.',
        );
      }
      if ((resumeSteps['ssh-key'] as Map?)?['state'] == 'done' &&
          answers.disablePasswordLogin &&
          !_login.usesKey) {
        throw StateError(
          'Reconnect using the verified SSH key saved by this setup before resuming password-login protection.',
        );
      }
    }
    _setupDraft = ProvisioningDraft(
      runId: runId,
      answers: answers,
      secrets: secrets.forTemplate(),
    );
    installation = started;
    try {
      if (remember) {
        await vault.saveSetup(_login.host, _login.port, _setupDraft!);
      }
    } catch (_) {
      try {
        installation = await _active.run('lifecycle-finish', [runId, 'failed']);
      } catch (_) {}
      throw StateError(
        'Could not protect setup recovery answers in the OS vault. Unlock the vault and retry; no setup step was started.',
      );
    }
    final previousSteps = (started['steps'] as Map?) ?? const {};
    const onceOnlySteps = {
      'upgrade',
      'root-password',
      'administrator',
      'ssh-public-key',
      'ssh-key',
    };
    tasks = work.map((item) => SetupTask(item.$2)).toList();
    _notify();
    try {
      for (var i = 0; i < work.length; i++) {
        final (id, _, execute) = work[i];
        final task = tasks[i];
        if (resumeRunId != null &&
            onceOnlySteps.contains(id) &&
            (previousSteps[id] as Map?)?['state'] == 'done') {
          task.state = TaskState.done;
          _append('[SETUP] Keeping completed step: ${task.label}.');
          continue;
        }
        task.state = TaskState.running;
        message = task.label;
        _append('[SETUP ${i + 1}/${work.length}] ${task.label}');
        _notify();
        try {
          await _active.run('lifecycle-step', [runId, id, 'running']);
          await execute();
          await _active.run('lifecycle-step', [runId, id, 'done']);
          task.state = TaskState.done;
        } catch (_) {
          task.state = TaskState.failed;
          try {
            await _active.run('lifecycle-step', [runId, id, 'failed']);
          } catch (_) {}
          _append(
            '[SETUP] Stopped at: ${task.label}. Earlier completed steps remain applied.',
          );
          rethrow;
        }
        _notify();
      }
      installation = await _active.run('lifecycle-finish', [runId, 'complete']);
    } catch (_) {
      try {
        installation = await _active.run('lifecycle-finish', [runId, 'failed']);
      } catch (_) {}
      rethrow;
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
        server['awg_deployment'] != 'amnezia' &&
        server['interface'] is String)
      server['interface'] as String,
    for (final item in server['external_awg'] as List? ?? [])
      if (item['running'] == true &&
          !(server['awg_deployment'] == 'amnezia' &&
              item['source'] == 'amnezia-awg2' &&
              (server['awg_shared_guard'] != true ||
                  server['kernel'] != true ||
                  server['userspace'] == true ||
                  server['awg_error'] != null)))
        item['source'] as String,
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

  bool _sameSocksTarget(
    ({String? containerId, String? source, int port})? target,
    Map<String, dynamic> actual,
  ) =>
      target != null &&
      target.containerId != null &&
      target.source != null &&
      actual['socks5'] == true &&
      actual['socks5_access'] == 'private' &&
      actual['socks5_private_supported'] != false &&
      actual['socks5_error'] == null &&
      actual['socks5_container_id'] == target.containerId &&
      actual['socks5_source'] == target.source &&
      actual['socks5_port'] == target.port;

  Future<void> _closeSocksTunnel() async {
    final previous = socksTunnel;
    socksTunnel = null;
    _socksTunnelTarget = null;
    await previous?.close();
  }

  /// Keep the tunnel only when fresh non-secret evidence identifies its target.
  Future<void> _reconcileSocksStatus(Map<String, dynamic> actual) async {
    if (socksTunnel != null && !_sameSocksTarget(_socksTunnelTarget, actual)) {
      await _closeSocksTunnel();
    }
  }

  Future<void> _readSocks() async {
    socks = null;
    _socksReadTarget = null;
    final Map<String, dynamic> result;
    try {
      result = await _active.run('socks-info');
      final port = result['port'];
      if (port is! int ||
          port < 1 ||
          port > 65535 ||
          result['user'] is! String ||
          result['password'] is! String ||
          !{'public', 'private'}.contains(result['access'] ?? 'public')) {
        throw const FormatException(
          'The SOCKS5 connection details are invalid.',
        );
      }
    } catch (_) {
      await _closeSocksTunnel();
      rethrow;
    }
    final containerId = result['container_id'];
    final source = result['source'];
    _socksReadTarget = (
      containerId:
          containerId is String &&
              RegExp(r'^[a-f0-9]{64}$').hasMatch(containerId)
          ? containerId
          : null,
      source: source is String && source.isNotEmpty ? source : null,
      port: result['port'] as int,
    );
    server['socks5_port'] = result['port'];
    server['socks5_access'] = result['access'] ?? 'public';
    server['socks5_container_id'] = _socksReadTarget!.containerId;
    server['socks5_source'] = _socksReadTarget!.source;
    server['socks5'] = true;
    server['socks5_configured'] = true;
    server.remove('socks5_error');
    if (server['socks5_access'] == 'private') {
      // The private info command already verified the daemon requirement.
      server['socks5_private_supported'] = true;
    }
    await _reconcileSocksStatus(server);
    socks = ConnectionDetails(
      host: result['access'] == 'private' ? '127.0.0.1' : _login.host,
      port: result['access'] == 'private' && socksTunnel != null
          ? socksTunnel!.port
          : result['port'] as int,
      user: result['user'] as String,
      password: result['password'] as String,
    );
    _secrets.add(socks!.password);
  }

  Future<bool> startSocksTunnel() => _guard(() async {
    await _closeSocksTunnel();
    await _readSocks();
    if (server['socks5_access'] != 'private') {
      throw StateError('Select private SOCKS5 access first.');
    }
    socksTunnel = await SocksTunnel.start(
      _active.connection.client,
      socks!.port,
    );
    _socksTunnelTarget = _socksReadTarget;
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
    await _closeSocksTunnel();
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
    await _closeSocksTunnel();
    socks = null;
    await _active.run('dependencies');
    await _active.run('socks-install', [
      '$port',
      user,
      password,
      replace ? 'yes' : 'no',
      access,
    ]);
    await _active.run('socks-check');
    await _refresh();
    if ((security?['firewall'] as Map?)?['managed'] == true) {
      await _securityApply({'firewall': true});
    }
    await _readSocks();
    message = 'SOCKS5 credentials verified. AmneziaVPN caches credentials locally; update or re-add its SOCKS5 connection to use the new access.';
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
