import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:dartssh2/dartssh2.dart';

import 'ssh_connection.dart';

/// Server input is sent over SSH stdin, never interpolated into commands.
class RemoteBackend {
  RemoteBackend(
    this.connection,
    this.username, {
    this.commandTimeout = const Duration(minutes: 45),
  });
  final Duration commandTimeout;
  final SshConnection connection;
  final String username;
  String? _work;
  Future<void>? _preparing;
  Future<void>? _closing;
  bool _busy = false;
  bool _closed = false;
  final _sessions = <SSHSession>{};
  final output = StreamController<String>.broadcast();

  String get _prefix => username == 'root'
      ? ''
      : 'sudo -n env "SSH_CONNECTION=\$SSH_CONNECTION" ';

  void _checkOpen() {
    if (_closed) throw StateError('SSH backend is closed.');
  }

  void _emit(String text) {
    if (!_closed) {
      output.add(text.replaceAll(RegExp(r'\x1B\[[0-?]*[ -/]*[@-~]'), ''));
    }
  }

  Future<T> _exclusive<T>(Future<T> Function() action) async {
    _checkOpen();
    if (_busy) throw StateError('Another server operation is already running.');
    _busy = true;
    try {
      return await action();
    } finally {
      _busy = false;
    }
  }

  Future<SSHSession> _execute(String command, {SSHPtyConfig? pty}) async {
    _checkOpen();
    final session = await connection.client.execute(command, pty: pty);
    if (_closed) {
      session.close();
      throw StateError('SSH backend is closed.');
    }
    _sessions.add(session);
    return session;
  }

  Stream<List<int>> _bounded(Stream<List<int>> source) async* {
    var received = 0;
    await for (final bytes in source) {
      received += bytes.length;
      if (received > 8 * 1024 * 1024) {
        throw StateError('Server output exceeded the safe response limit.');
      }
      yield bytes;
    }
  }

  Future<void> prepare() {
    _checkOpen();
    if (_work != null) return Future<void>.value();
    return _preparing ??= _prepare().whenComplete(() => _preparing = null);
  }

  Future<void> _prepare() async {
    if (username != 'root') {
      final sudo = await connection.client.runWithResult('sudo -n true');
      if (sudo.exitCode != 0) {
        throw StateError('This account needs passwordless sudo.');
      }
    }
    _checkOpen();
    final result = await connection.client.runWithResult(
      'umask 077; mktemp -d /tmp/ashapp.XXXXXXXXXX',
    );
    final created = utf8.decode(result.stdout).trim();
    if (result.exitCode != 0 ||
        !RegExp(r'^/tmp/ashapp\.[A-Za-z0-9]+$').hasMatch(created)) {
      throw StateError('Could not prepare the server directory.');
    }
    try {
      for (final name in [
        'remote.sh',
        'clients.py',
        'amnezia_clients.py',
        'amneziawg-install.sh',
        'awg_setup.py',
        'vless_manager.py',
      ]) {
        _checkOpen();
        final asset = await rootBundle.load('assets/$name');
        final session = await _execute('umask 077; cat > $created/$name');
        try {
          await Future.wait([
            session.done,
            session.stdout.drain<void>(),
            session.stderr.drain<void>(),
            () async {
              session.stdin.add(
                asset.buffer.asUint8List(
                  asset.offsetInBytes,
                  asset.lengthInBytes,
                ),
              );
              await session.stdin.close();
            }(),
          ], eagerError: true);
          if (session.exitCode != 0) {
            throw StateError('Could not upload the server files.');
          }
        } finally {
          _sessions.remove(session);
          session.close();
        }
      }
      _checkOpen();
      // Publish readiness only after every upload has succeeded.
      _work = created;
    } catch (_) {
      await _removeWork(created);
      rethrow;
    }
  }

  Future<Map<String, dynamic>> run(
    String action, [
    List<String> fields = const [],
  ]) => _exclusive(() => _run(action, fields));

  Future<Map<String, dynamic>> _run(
    String action, [
    List<String> fields = const [],
  ]) async {
    if (!RegExp(r'^[a-z-]+$').hasMatch(action) ||
        fields.any((s) => s.contains('\x00'))) {
      throw ArgumentError('Invalid server action or parameters.');
    }
    await prepare();
    final session = await _execute('${_prefix}bash $_work/remote.sh $action');
    final result = <String, dynamic>{};
    String? remoteError;
    try {
      await Future.wait([
        session.done,
        _bounded(session.stdout.cast<List<int>>())
            .transform(utf8.decoder)
            .transform(const LineSplitter())
            .forEach((line) {
              if (line.startsWith('ASHAPP_JSON:')) {
                final parsed = jsonDecode(
                  line.substring('ASHAPP_JSON:'.length),
                );
                if (parsed is! Map<String, dynamic>) {
                  throw const FormatException('Invalid server response.');
                }
                result.addAll(parsed);
              } else {
                _emit(line);
              }
            }),
        _bounded(
          session.stderr.cast<List<int>>(),
        ).transform(utf8.decoder).transform(const LineSplitter()).forEach((
          line,
        ) {
          if (line.startsWith('ERROR: ')) {
            final reason = line.substring(7).trim();
            if (reason.isNotEmpty) {
              remoteError = reason.length > 500
                  ? 'The server reported an error. Check the activity details.'
                  : reason;
            }
          }
          _emit(line);
        }),
        () async {
          session.stdin.add(
            Uint8List.fromList(
              utf8.encode(fields.isEmpty ? '' : '${fields.join('\x00')}\x00'),
            ),
          );
          await session.stdin.close();
        }(),
      ], eagerError: true).timeout(commandTimeout);
      _checkOpen();
      if (session.exitCode != 0) {
        throw StateError(remoteError ?? 'Server action $action failed.');
      }
      return result;
    } finally {
      _sessions.remove(session);
      session.close();
    }
  }

  Future<void> _removeWork(String path) async {
    if (!connection.client.isClosed) {
      try {
        await connection.client.run(
          'rm -f $path/remote.sh $path/clients.py $path/amnezia_clients.py $path/amneziawg-install.sh $path/awg_setup.py $path/vless_manager.py; rmdir $path',
        );
      } catch (_) {
        /* The connection may already be lost. */
      }
    }
  }

  Future<void> close() => _closing ??= _close();

  Future<void> _close() async {
    _closed = true;
    for (final session in _sessions.toList()) {
      session.close();
    }
    final path = _work;
    _work = null;
    if (path != null) await _removeWork(path);
    await output.close();
  }
}
