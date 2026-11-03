import 'dart:convert';
import 'dart:io';

import 'package:ashapp/private_export.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('ashapp/private-export');
  tearDown(
    () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null),
  );

  test('private bytes go only through the platform export boundary', () async {
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return null;
        });
    await savePrivateExport('/synthetic/export.conf', 'private-placeholder\n');
    expect(received!.method, 'save');
    final arguments = received!.arguments as Map;
    expect(arguments['path'], '/synthetic/export.conf');
    expect(arguments['bytes'], utf8.encode('private-placeholder\n'));
  }, skip: !Platform.isWindows && !Platform.isMacOS);

  test(
    'native protection failure never falls back to plaintext file writing',
    () async {
      final temporary = await Directory.systemTemp.createTemp('ashapp_export_');
      addTearDown(() => temporary.delete(recursive: true));
      final path = '${temporary.path}${Platform.pathSeparator}private.conf';
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (_) async {
            throw PlatformException(code: 'export_failed');
          });
      await expectLater(
        savePrivateExport(path, 'private-placeholder'),
        throwsA(isA<PlatformException>()),
      );
      expect(await File(path).exists(), isFalse);
    },
    skip: !Platform.isWindows && !Platform.isMacOS,
  );
}
