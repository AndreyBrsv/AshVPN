import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Serializes access across repository instances and replaces complete files.
class JsonFileStore {
  JsonFileStore(this.file);

  final File file;
  static final _pending = <String, Future<void>>{};

  Future<T> _locked<T>(Future<T> Function() action) async {
    final key = file.absolute.path;
    final previous = _pending[key] ?? Future<void>.value();
    final released = Completer<void>();
    _pending[key] = released.future;
    await previous;
    try {
      await file.parent.create(recursive: true);
      final lock = await File('${file.path}.lock').open(mode: FileMode.append);
      try {
        await lock.lock(FileLock.blockingExclusive);
        return await action();
      } finally {
        await lock.close();
      }
    } finally {
      released.complete();
      if (identical(_pending[key], released.future)) _pending.remove(key);
    }
  }

  Future<Object?> _read() async {
    if (!await file.exists()) return null;
    final value = jsonDecode(await file.readAsString());
    if (value == null) throw const FormatException('Invalid JSON document.');
    return value;
  }

  Future<Object?> read() => _locked(_read);

  Future<void> _write(Object? value) async {
    final temporary = await file.parent.createTemp('.ashapp-write-');
    try {
      final content = File.fromUri(temporary.uri.resolve('content.json'));
      await content.writeAsString(jsonEncode(value), flush: true);
      await content.rename(file.path);
    } finally {
      await temporary.delete(recursive: true);
    }
  }

  Future<void> write(Object? value) => _locked(() => _write(value));

  /// Reads, validates and merges a document while holding the same file lock.
  Future<void> update(Future<Object?> Function(Object? current) change) =>
      _locked(() async {
        final current = await _read();
        final next = await change(current);
        if (!identical(next, current)) await _write(next);
      });
}
