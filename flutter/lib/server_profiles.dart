import 'dart:io';

import 'package:path/path.dart' as path;

import 'json_file_store.dart';

/// The persistent profile deliberately contains only an address and ports.
class ServerProfile {
  const ServerProfile({required this.ip, required this.sshPort});
  final String ip;
  final int sshPort;

  Map<String, Object> toJson() => {'ip': ip, 'ssh_port': sshPort};

  static ServerProfile fromJson(Object? raw) {
    if (raw is! Map || raw['ip'] is! String || raw['ssh_port'] is! int) {
      throw const FormatException('Invalid server record.');
    }
    final ip = raw['ip'] as String;
    final port = raw['ssh_port'] as int;
    if (InternetAddress.tryParse(ip)?.type != InternetAddressType.IPv4 ||
        port < 1 ||
        port > 65535) {
      throw const FormatException('Invalid server address or port.');
    }
    return ServerProfile(ip: ip, sshPort: port);
  }
}

Directory appDataDirectory() {
  final home = Platform.environment['HOME'];
  final base = Platform.isWindows
      ? Platform.environment['LOCALAPPDATA']
      : home == null
      ? null
      : Platform.isMacOS
      ? path.join(home, 'Library', 'Application Support')
      : path.join(home, '.local', 'share');
  if (base == null || base.isEmpty) {
    throw const FileSystemException(
      'Could not locate the application data directory.',
    );
  }
  return Directory(path.join(base, 'Ashapp'));
}

class ServerProfiles {
  ServerProfiles(this.file);
  final File file;

  Future<List<ServerProfile>> load() async {
    final data = await JsonFileStore(file).read();
    if (data == null) return [];
    if (data is! Map || data['version'] != 1 || data['servers'] is! List) {
      throw const FormatException('Could not read saved servers.');
    }
    return (data['servers'] as List).map(ServerProfile.fromJson).toList();
  }

  Future<void> save(List<ServerProfile> profiles) async {
    final records = profiles
        .map((item) => ServerProfile.fromJson(item.toJson()).toJson())
        .toList();
    await JsonFileStore(file).write({'version': 1, 'servers': records});
  }

  Future<void> upsert(ServerProfile profile) =>
      JsonFileStore(file).update((root) async {
        final records = root == null ? <ServerProfile>[] : _decode(root);
        return {
          'version': 1,
          'servers': [
            ...records.where(
              (p) => p.ip != profile.ip || p.sshPort != profile.sshPort,
            ),
            ServerProfile.fromJson(profile.toJson()),
          ].map((p) => p.toJson()).toList(),
        };
      });

  Future<void> remove(ServerProfile profile) => JsonFileStore(file).update(
    (root) async => {
      'version': 1,
      'servers': (root == null ? <ServerProfile>[] : _decode(root))
          .where((p) => p.ip != profile.ip || p.sshPort != profile.sshPort)
          .map((p) => p.toJson())
          .toList(),
    },
  );

  List<ServerProfile> _decode(Object root) {
    if (root is! Map || root['version'] != 1 || root['servers'] is! List) {
      throw const FormatException('Could not read saved servers.');
    }
    return (root['servers'] as List).map(ServerProfile.fromJson).toList();
  }
}
