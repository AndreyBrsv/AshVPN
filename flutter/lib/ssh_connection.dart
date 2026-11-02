import 'dart:convert';
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';

import 'server_profiles.dart';
import 'host_key_store.dart';

export 'host_key_store.dart' show ConfirmHost;

class SshConnection {
  SshConnection.fromClient(this.client);
  final SSHClient client;

  static Future<SshConnection> connect({
    required String host,
    required int port,
    required String username,
    required String password,
    required ConfirmHost confirmHost,
  }) async {
    final dir = appDataDirectory();
    await dir.create(recursive: true);
    final knownFile = File(
      '${dir.path}${Platform.pathSeparator}known_hosts.json',
    );
    final known = KnownHosts(knownFile);
    final key = '$host:$port';
    final socket = await SSHSocket.connect(
      host,
      port,
      timeout: const Duration(seconds: 15),
    );
    final client = SSHClient(
      socket,
      username: username,
      onPasswordRequest: () => password,
      onVerifyHostKey: (type, fingerprint) async {
        return known.verify(key, type, utf8.decode(fingerprint), confirmHost);
      },
    );
    try {
      await client.authenticated.timeout(const Duration(minutes: 2));
      return SshConnection.fromClient(client);
    } catch (_) {
      client.close();
      rethrow;
    }
  }

  Future<void> close() => client.close();
}
