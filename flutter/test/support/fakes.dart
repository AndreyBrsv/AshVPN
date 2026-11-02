import 'dart:async';
import 'dart:io';

import 'package:ashapp/credential_vault.dart';
import 'package:ashapp/remote_backend.dart';
import 'package:ashapp/server_profiles.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/ssh_connection.dart';
import 'package:ashapp/template_repository.dart';
import 'package:ashapp/workspace_controller.dart';
import 'package:dartssh2/dartssh2.dart';
import 'package:flutter_test/flutter_test.dart';

class MemorySecrets implements SecretStore {
  final values = <String, String>{};
  bool fail = false;
  bool failDelete = false;
  @override
  Future<String?> read(String key) async => values[key];
  @override
  Future<void> write(String key, String value) async {
    if (fail) throw StateError('Vault locked.');
    values[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    if (failDelete) throw StateError('Vault locked.');
    values.remove(key);
  }
}

class MemoryProfiles extends ServerProfiles {
  MemoryProfiles() : super(File('unused-test-profiles.json'));
  List<ServerProfile> records = [];
  bool fail = false;
  @override
  Future<List<ServerProfile>> load() async => List.of(records);
  @override
  Future<void> upsert(ServerProfile profile) async {
    if (fail) throw StateError('Profile metadata unavailable.');
    records.removeWhere(
      (p) => p.ip == profile.ip && p.sshPort == profile.sshPort,
    );
    records.add(profile);
  }

  @override
  Future<void> remove(ServerProfile profile) async {
    records.removeWhere(
      (p) => p.ip == profile.ip && p.sshPort == profile.sshPort,
    );
  }
}

class MemoryTemplates extends TemplateRepository {
  MemoryTemplates() : super(File('unused-test-templates.json'));
  List<ServerTemplate> records = [];
  final pending = <String>{};
  @override
  Future<List<ServerTemplate>> load() async => List.of(records);
  @override
  Future<String?> upsert(ServerTemplate template) async {
    final previous = records.where((t) => t.name == template.name).firstOrNull;
    records.removeWhere((t) => t.name == template.name);
    records.add(template);
    if (previous != null) pending.add(previous.credentialsRef ?? previous.name);
    return previous == null ? null : previous.credentialsRef ?? previous.name;
  }

  @override
  Future<String?> remove(String name) async {
    final previous = records.where((t) => t.name == name).firstOrNull;
    records.removeWhere((t) => t.name == name);
    if (previous != null) pending.add(previous.credentialsRef ?? previous.name);
    return previous == null ? null : previous.credentialsRef ?? previous.name;
  }

  @override
  Future<List<String>> pendingDeletions() async => pending
      .where((ref) => !records.any((t) => (t.credentialsRef ?? t.name) == ref))
      .toList();
  @override
  Future<void> acknowledgeDeletion(String ref) async {
    pending.remove(ref);
  }
}

class FakeClient extends Fake implements SSHClient {
  bool closed = false;
  final finished = Completer<void>();
  @override
  Future<void> get done => finished.future;
  @override
  bool get isClosed => closed;
  @override
  Future<void> close() async {
    closed = true;
    if (!finished.isCompleted) finished.complete();
  }
}

class FakeServer {
  final state = <String, dynamic>{
    'awg': false,
    'awg_configured': false,
    'kernel': false,
    'userspace': false,
    'socks5': false,
    'icmp_blocked': false,
    'ssh': {'permitrootlogin': 'yes', 'passwordauthentication': 'yes'},
  };
  final clients = <String>{};
  List<Map<String, dynamic>>? clientRows;
  List<String> clientWarnings = [];
  final users = <String>{};
  final calls = <(String, List<String>, String)>[];
  String? failAction;
  String failureMessage = 'Simulated server failure.';
  String? configuration;
  Map<String, dynamic>? vlessConnection;
  String? revokeWarning;
  bool denyAdmin = false;
  Completer<void>? gate;
  int socksPort = 1080;
  String socksUser = 'proxy', socksPassword = 'test-proxy-placeholder';
}

class FakeBackend extends Fake implements RemoteBackend {
  FakeBackend(this.connection, this.username, this.server);
  @override
  final SshConnection connection;
  @override
  final String username;
  final FakeServer server;
  @override
  final output = StreamController<String>.broadcast();
  bool closed = false;
  @override
  Future<Map<String, dynamic>> run(
    String action, [
    List<String> fields = const [],
  ]) async {
    if (closed) throw StateError('Closed backend.');
    server.calls.add((action, List.of(fields), username));
    await server.gate?.future;
    if (server.failAction == action ||
        (action == 'preflight' && username != 'root' && server.denyAdmin)) {
      throw StateError(server.failureMessage);
    }
    switch (action) {
      case 'preflight':
        return {'python': true};
      case 'status':
        return Map.of(server.state);
      case 'clients':
        return {
          'clients':
              server.clientRows ??
              [
                for (final n in server.clients) {'name': n, 'handshake': 0},
              ],
          'warnings': server.clientWarnings,
        };
      case 'users':
        return {
          'users': [
            for (final n in server.users)
              {'name': n, 'uid': 1000, 'shell': '/bin/bash'},
          ],
        };
      case 'create-user':
        server.users.add(fields[0]);
      case 'ssh-config':
        if (fields[1] == 'no') {
          server.state['ssh'] = {
            'permitrootlogin': 'no',
            'passwordauthentication': 'yes',
          };
        }
      case 'icmp':
        server.state['icmp_blocked'] = true;
      case 'icmp-unblock':
        server.state['icmp_blocked'] = false;
      case 'install-awg-configured':
        server.state.addAll({
          'awg': true,
          'interface': 'awg0',
          'awg_configured': true,
          'kernel': true,
          'awg_port': int.parse(fields[1]),
        });
      case 'add-client':
        server.clients.add(fields[0]);
      case 'revoke-client':
        server.clients.remove(fields[0]);
        if (server.revokeWarning != null) {
          return {'revoked': true, 'warning': server.revokeWarning};
        }
      case 'rename-client':
        server.clients.remove(fields[0]);
        server.clients.add(fields[3]);
        for (final row in server.clientRows ?? <Map<String, dynamic>>[]) {
          if (row['source'] == fields[1] && row['public_key'] == fields[2]) {
            row['name'] = fields[3];
          }
        }
      case 'get-client':
        if (fields.length > 1 && fields[1] == 'vless-reality') {
          return {'connection': server.vlessConnection};
        }
        return {
          'config': server.configuration ?? 'private-config-test-placeholder',
        };
      case 'import-client':
        server.configuration = fields[3];
        for (final row in server.clientRows ?? <Map<String, dynamic>>[]) {
          if (row['source'] == fields[1] && row['public_key'] == fields[2]) {
            row['can_export'] = true;
          }
        }
      case 'socks-install':
        server.state.addAll({'socks5': true, 'socks5_configured': true});
        server.socksPort = int.parse(fields[0]);
        server.socksUser = fields[1];
        server.socksPassword = fields[2];
      case 'socks-info':
        return {
          'port': server.socksPort,
          'user': server.socksUser,
          'password': server.socksPassword,
        };
      case 'socks-control':
        server.state['socks5'] = fields[0] != 'stop';
      case 'awg-control':
        server.state['awg'] = fields[0] != 'stop';
      case 'install-vless':
        if (server.state['vless_configured'] == true) {
          return {'preserved': true, ...server.state};
        }
        server.state.addAll({
          'vless': true,
          'vless_configured': true,
          'vless_port': int.parse(fields[1]),
          'vless_sni': fields[2],
        });
        return Map.of(server.state);
      case 'vless-control':
        server.state['vless'] = fields[0] != 'stop';
    }
    return {};
  }

  @override
  Future<void> close() async {
    if (!closed) {
      closed = true;
      await output.close();
    }
  }
}

class Harness {
  final store = MemorySecrets();
  final profiles = MemoryProfiles();
  final templates = MemoryTemplates();
  final backends = <FakeBackend>[];
  final servers = <String, FakeServer>{};
  final logins = <({String host, String user, String password})>[];
  final endpoints = <SshConnection, String>{};
  Completer<void>? connectGate;
  late final vm = WorkspaceController(
    profilesRepository: profiles,
    templatesRepository: templates,
    vault: CredentialVault(store),
    connector: connect,
    backendFactory: createBackend,
  );
  FakeServer get server => servers.putIfAbsent('203.0.113.10', FakeServer.new);
  Future<SshConnection> connect({
    required String host,
    required int port,
    required String username,
    required String password,
    required ConfirmHost confirmHost,
  }) async {
    logins.add((host: host, user: username, password: password));
    await connectGate?.future;
    final connection = SshConnection.fromClient(FakeClient());
    endpoints[connection] = port == 22 ? host : '$host:$port';
    return connection;
  }

  FakeBackend createBackend(SshConnection connection, String username) {
    final server = servers.putIfAbsent(endpoints[connection]!, FakeServer.new);
    final backend = FakeBackend(connection, username, server);
    backends.add(backend);
    return backend;
  }
}
