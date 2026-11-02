import 'dart:io';

import 'package:ashapp/main.dart';
import 'package:ashapp/setup_wizard.dart';
import 'package:ashapp/server_profiles.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/template_repository.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

void main() {
  test('concurrent profile saves leave a complete readable file', () async {
    final dir = await Directory.systemTemp.createTemp('ashapp_review_');
    addTearDown(() => dir.delete(recursive: true));
    final file = File('${dir.path}/servers.json');
    final stores = [ServerProfiles(file), ServerProfiles(file)];
    await Future.wait([
      for (var index = 0; index < stores.length; index++)
        stores[index].save([
          ServerProfile(ip: '203.0.113.${index + 1}', sshPort: 22),
        ]),
    ]);
    expect((await stores.last.load()).single.ip, '203.0.113.2');
  });

  test('templates own an immutable copy of their client names', () {
    final names = ['phone'];
    final template = ServerTemplate(
      name: 'Travel',
      blockPing: false,
      disableRoot: false,
      installAwg: true,
      installSocks: false,
      awgPort: 585,
      clientNames: names,
    );
    names.add('laptop');
    expect(template.clientNames, ['phone']);
    expect(() => template.clientNames.clear(), throwsUnsupportedError);
  });

  test('malformed template records report a format error', () async {
    final dir = await Directory.systemTemp.createTemp('ashapp_review_');
    addTearDown(() => dir.delete(recursive: true));
    final file = File('${dir.path}/templates.json');
    await file.writeAsString('{"version":1,"templates":[null]}');
    await expectLater(TemplateRepository(file).load(), throwsFormatException);
  });

  testWidgets('setup sections remain usable in a short window', (tester) async {
    tester.view.physicalSize = const Size(900, 560);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final h = Harness();
    addTearDown(h.vm.dispose);
    await tester.pumpWidget(
      AshappApp(home: SetupWizard(controller: h.vm, editTemplate: true)),
    );
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });
}
