import 'dart:convert';
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';

import 'server_profiles.dart';
import 'host_key_store.dart';
import 'connection_details.dart';

export 'host_key_store.dart' show ConfirmHost;

class SshConnection {
  SshConnection.fromClient(this.client);
  final SSHClient client;

  static Future<SshConnection> connectWithKey(
    ConnectionDetails details,
    ConfirmHost confirmHost,
  ) => connect(
    host: details.host,
    port: details.port,
    username: details.user,
    password: '',
    privateKey: details.privateKey,
    keyPassphrase: details.keyPassphrase,
    confirmHost: confirmHost,
  );

  static Future<SshConnection> connect({
    required String host,
    required int port,
    required String username,
    required String password,
    required ConfirmHost confirmHost,
    String privateKey = '',
    String keyPassphrase = '',
  }) async {
    final dir = appDataDirectory();
    await dir.create(recursive: true);
    final knownFile = File(
      '${dir.path}${Platform.pathSeparator}known_hosts.json',
    );
    final known = KnownHosts(knownFile);
    final key = '$host:$port';
    final identities = privateKey.isEmpty
        ? null
        : SSHKeyPair.fromPem(
            privateKey,
            keyPassphrase.isEmpty ? null : keyPassphrase,
          );
    final socket = await SSHSocket.connect(
      host,
      port,
      timeout: const Duration(seconds: 15),
    );
    final client = SSHClient(
      socket,
      username: username,
      identities: identities,
      onPasswordRequest: privateKey.isEmpty ? () => password : null,
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
