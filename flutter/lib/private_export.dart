import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

/// Restricts a selected export before any private key bytes reach the file.
Future<void> savePrivateExport(String path, String contents) async {
  if (Platform.isMacOS || Platform.isWindows) {
    await const MethodChannel('ashapp/private-export').invokeMethod<void>(
      'save',
      {'path': path, 'bytes': Uint8List.fromList(utf8.encode(contents))},
    );
    return;
  }
  throw UnsupportedError('Private exports require Windows or macOS.');
}
