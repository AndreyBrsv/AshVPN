import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as path;

/// Used only by the explicitly approved uninstall flow, before removing binaries.
/// Vault deletion comes first: a locked vault must not become orphaned by uninstall.
Future<void> eraseLocalData({
  required Directory directory,
  required Future<void> Function() eraseSecrets,
}) async {
  if (path.basename(directory.absolute.path) != 'Ashapp' ||
      await FileSystemEntity.type(directory.path, followLinks: false) ==
          FileSystemEntityType.link) {
    throw const FileSystemException('Unsafe application data directory.');
  }
  // Reject redirected ancestors before touching either settings or credentials.
  final parent = directory.absolute.parent;
  if (!path.equals(await parent.resolveSymbolicLinks(), parent.path)) {
    throw const FileSystemException('Redirected application data directory.');
  }
  await eraseSecrets();
  if (await directory.exists()) await directory.delete(recursive: true);
}

Future<void> eraseAshappSecrets() async {
  const storage = FlutterSecureStorage(
    mOptions: MacOsOptions(usesDataProtectionKeychain: false),
  );
  // The plugin's default Keychain service can be shared. Never deleteAll().
  final entries = await storage.readAll();
  for (final key
      in entries.keys.where((key) => key.startsWith('ashapp.')).toList()) {
    await storage.delete(key: key);
  }
  if ((await storage.readAll()).keys.any((key) => key.startsWith('ashapp.'))) {
    throw const FileSystemException('Protected data could not be removed.');
  }
}
