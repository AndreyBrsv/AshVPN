import 'dart:io';

import 'json_file_store.dart';

typedef ConfirmHost = Future<bool> Function(String type, String fingerprint);

class HostKeyChange implements Exception {
  const HostKeyChange({
    required this.endpoint,
    required this.previousKey,
    required this.type,
    required this.fingerprint,
  });

  final String endpoint, previousKey, type, fingerprint;
  String get replacementKey => '$type $fingerprint';
}

class KnownHosts {
  KnownHosts(File file) : _store = JsonFileStore(file);
  final JsonFileStore _store;

  Future<void> forget(String endpoint) => _store.update((raw) async {
    if (raw == null) return raw;
    if (raw is! Map<String, dynamic> || raw.values.any((v) => v is! String)) {
      throw const FormatException('Invalid SSH host-key file.');
    }
    if (!raw.containsKey(endpoint)) return raw;
    return Map<String, dynamic>.from(raw)..remove(endpoint);
  });

  Future<bool> verify(
    String endpoint,
    String type,
    String fingerprint,
    ConfirmHost confirm, {
    void Function(HostKeyChange)? onChanged,
  }) async {
    var accepted = false;
    await _store.update((raw) async {
      if (raw != null &&
          (raw is! Map<String, dynamic> ||
              raw.values.any((value) => value is! String))) {
        throw const FormatException('Invalid SSH host-key file.');
      }
      final known = raw as Map<String, dynamic>? ?? <String, dynamic>{};
      final value = '$type $fingerprint';
      if (known.containsKey(endpoint)) {
        accepted = known[endpoint] == value;
        if (!accepted) {
          onChanged?.call(
            HostKeyChange(
              endpoint: endpoint,
              previousKey: known[endpoint]!,
              type: type,
              fingerprint: fingerprint,
            ),
          );
        }
        return raw;
      }
      accepted = await confirm(type, fingerprint);
      return accepted ? {...known, endpoint: value} : raw;
    });
    return accepted;
  }

  /// Replaces only the exact key the user reviewed, preserving concurrent edits.
  Future<bool> acceptChange(HostKeyChange change) async {
    var accepted = false;
    await _store.update((raw) async {
      if (raw is! Map<String, dynamic> || raw.values.any((v) => v is! String)) {
        throw const FormatException('Invalid SSH host-key file.');
      }
      if (raw[change.endpoint] == change.replacementKey) {
        accepted = true;
        return raw;
      }
      if (raw[change.endpoint] != change.previousKey) return raw;
      accepted = true;
      return {...raw, change.endpoint: change.replacementKey};
    });
    return accepted;
  }
}
