import 'dart:convert';
import 'dart:io';

import 'package:ashapp/server_profiles.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('profiles persist only IP and port', () async {
    final dir = await Directory.systemTemp.createTemp('ashapp_test_');
    try {
      final file = File('${dir.path}/servers.json');
      final store = ServerProfiles(file);
      await store.save([const ServerProfile(ip: '203.0.113.5', sshPort: 22)]);
      final item =
          (jsonDecode(await file.readAsString())['servers'] as List).single;
      expect((item as Map).keys.toSet(), {'ip', 'ssh_port'});
      expect((await store.load()).single.ip, '203.0.113.5');
    } finally {
      await dir.delete(recursive: true);
    }
  });
}
