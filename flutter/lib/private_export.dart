import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

/// Restricts a selected export before any private key bytes reach the file.
Future<void> savePrivateExport(String path, String contents) async {
  if (Platform.isMacOS) {
    await const MethodChannel('ashapp/private-export').invokeMethod<void>(
      'save',
      {'path': path, 'bytes': Uint8List.fromList(utf8.encode(contents))},
    );
    return;
  }
  if (!Platform.isWindows) {
    throw UnsupportedError('Private exports require Windows or macOS.');
  }
  final file = File(path);
  if (await FileSystemEntity.type(path, followLinks: false) ==
      FileSystemEntityType.link) {
    throw const FileSystemException('Choose a regular file.');
  }
  final output = await file.open(mode: FileMode.write);
  try {
    await output.writeFrom(utf8.encode(contents));
    await output.flush();
  } finally {
    await output.close();
  }
}
