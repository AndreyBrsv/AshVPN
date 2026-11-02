import 'dart:convert';

/// A saved configuration is reused verbatim for copy and QR, never regenerated.
class ClientConfiguration {
  const ClientConfiguration(this.content);
  static const maxBytes = 128 * 1024;
  final String content;

  bool get withinLimit =>
      content.length <= maxBytes &&
      !content.contains('\x00') &&
      utf8.encode(content).length <= maxBytes;

  String? _field(String section, String name) {
    String? active;
    final text = content.startsWith('\ufeff') ? content.substring(1) : content;
    for (final raw in const LineSplitter().convert(text)) {
      final line = raw.split('#').first.trim();
      if (line.startsWith('[') && line.endsWith(']')) {
        active = line.substring(1, line.length - 1);
      } else if (active == section && line.contains('=')) {
        final index = line.indexOf('=');
        if (line.substring(0, index).trim() != name) continue;
        return line.substring(index + 1).trim();
      }
    }
    return null;
  }

  String? get privateKey {
    final value = _field('Interface', 'PrivateKey');
    try {
      if (value != null &&
          value.length == 44 &&
          base64.decode(value).length == 32) {
        return value;
      }
    } on FormatException {
      return null;
    }
    return null;
  }

  List<String> get secrets => [
    if (privateKey case final String key) key,
    if (_field('Peer', 'PresharedKey') case final String key) key,
    if (_field('Interface', 'HeaderProtectionKey') case final String key) key,
  ];
}
