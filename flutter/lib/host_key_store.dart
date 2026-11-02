import 'dart:io';

import 'json_file_store.dart';

typedef ConfirmHost = Future<bool> Function(String type, String fingerprint);

class KnownHosts {
  KnownHosts(File file) : _store = JsonFileStore(file);
  final JsonFileStore _store;

  Future<bool> verify(
    String endpoint,
    String type,
    String fingerprint,
    ConfirmHost confirm,
  ) async {
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
        return raw;
      }
      accepted = await confirm(type, fingerprint);
      return accepted ? {...known, endpoint: value} : raw;
    });
    return accepted;
  }
}
