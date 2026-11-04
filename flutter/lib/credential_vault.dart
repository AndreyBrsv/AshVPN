import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'connection_details.dart';
import 'setup_secrets.dart';

abstract interface class SecretStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

class PlatformSecretStore implements SecretStore {
  // The macOS login Keychain avoids requiring Keychain Sharing provisioning.
  final _storage = const FlutterSecureStorage(
    mOptions: MacOsOptions(usesDataProtectionKeychain: false),
  );
  @override
  Future<String?> read(String key) => _storage.read(key: key);
  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);
  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}

/// No plaintext fallback: a locked or unavailable OS vault is reported to the UI.
class CredentialVault {
  CredentialVault(this.store);
  final SecretStore store;
  String _key(String scope, String id) =>
      'ashapp.$scope.${base64Url.encode(utf8.encode(id))}';
  String _endpoint(String host, int port) => '$host:$port';
  Future<void> saveConnection(
    ConnectionDetails details, {
    ConnectionDetails? additional,
  }) async {
    final key = _key('ssh', _endpoint(details.host, details.port));
    final current = await _credentials(details.host, details.port);
    final accounts = _accounts(current);
    accounts[details.user] = details.password;
    if (additional != null) {
      if (additional.host != details.host || additional.port != details.port) {
        throw ArgumentError('Credentials must belong to the same server.');
      }
      accounts[additional.user] = additional.password;
    }
    await store.write(
      key,
      jsonEncode({
        'user': details.user,
        'password': details.password,
        'accounts': accounts,
        'private_key': details.privateKey,
        'key_passphrase': details.keyPassphrase,
      }),
    );
  }

  Future<Map<String, dynamic>?> _credentials(String host, int port) async {
    final raw = await store.read(_key('ssh', _endpoint(host, port)));
    if (raw == null) return null;
    final value = jsonDecode(raw);
    if (value is! Map<String, dynamic> ||
        value['user'] is! String ||
        value['password'] is! String ||
        (value['private_key'] != null && value['private_key'] is! String) ||
        (value['key_passphrase'] != null &&
            value['key_passphrase'] is! String)) {
      throw const FormatException('Invalid saved credentials.');
    }
    _accounts(value);
    return value;
  }

  Map<String, String> _accounts(Map<String, dynamic>? current) {
    if (current == null) return {};
    final records = current['accounts'];
    if (records != null &&
        (records is! Map ||
            records.entries.any(
              (item) => item.key is! String || item.value is! String,
            ))) {
      throw const FormatException('Invalid saved account credentials.');
    }
    return {
      if (records != null) ...Map<String, String>.from(records as Map),
      current['user'] as String: current['password'] as String,
    };
  }

  Future<ConnectionDetails?> account(String host, int port, String user) async {
    final password = _accounts(await _credentials(host, port))[user];
    return password == null
        ? null
        : ConnectionDetails(
            host: host,
            port: port,
            user: user,
            password: password,
          );
  }

  Future<ConnectionDetails?> connection(String host, int port) async {
    final json = await _credentials(host, port);
    if (json == null) return null;
    return ConnectionDetails(
      host: host,
      port: port,
      user: json['user'] as String,
      password: json['password'] as String,
      privateKey: json['private_key'] as String? ?? '',
      keyPassphrase: json['key_passphrase'] as String? ?? '',
    );
  }

  Future<void> forgetConnection(String host, int port) =>
      store.delete(_key('ssh', _endpoint(host, port)));
  Future<void> saveTemplate(String name, SetupSecrets secrets) =>
      store.write(_key('template', name), jsonEncode(secrets.toVault()));
  Future<SetupSecrets> template(String name) async {
    final raw = await store.read(_key('template', name));
    if (raw == null) return const SetupSecrets();
    final json = jsonDecode(raw);
    if (json is! Map<String, dynamic>) {
      throw const FormatException('Invalid protected template.');
    }
    return SetupSecrets.fromVault(json);
  }

  Future<void> deleteTemplate(String name) =>
      store.delete(_key('template', name));
}
