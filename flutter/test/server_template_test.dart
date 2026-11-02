import 'dart:convert';
import 'dart:io';

import 'package:ashapp/server_template.dart';
import 'package:ashapp/template_repository.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('templates persist only non-secret settings', () async {
    final dir = await Directory.systemTemp.createTemp('ashapp_templates_');
    try {
      final file = File('${dir.path}/templates.json');
      final repository = TemplateRepository(file);
      await repository.save([
        ServerTemplate(
          name: 'Home',
          blockPing: true,
          disableRoot: false,
          installAwg: true,
          installSocks: false,
          awgPort: 585,
          clientNames: ['phone'],
        ),
      ]);
      final data = jsonDecode(await file.readAsString()) as Map;
      final fields = (data['templates'] as List).single as Map;
      expect(fields.keys.toSet(), {
        'name',
        'block_ping',
        'disable_root',
        'install_awg',
        'install_socks',
        'awg_port',
        'client_names',
        'upgrade_packages',
        'change_root_password',
        'create_admin',
        'awg_dns',
        'socks_port',
        'ssh_port',
        'install_vless',
        'vless_port',
        'reality_sni',
        'reality_fingerprint',
        'vless_client_names',
      });
      expect((await repository.load()).single.clientNames, ['phone']);
    } finally {
      await dir.delete(recursive: true);
    }
  });
}
