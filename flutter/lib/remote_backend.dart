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
  int _epoch = 0;
  final _sessions = <SSHSession>{};
  final output = StreamController<String>.broadcast();

  String get _prefix => username == 'root'
      ? ''
      : 'sudo -n env "SSH_CONNECTION=\$SSH_CONNECTION" ';

  void _checkOpen() {
    if (_closed) throw StateError('SSH backend is closed.');
  }

  void _checkEpoch(int epoch) {
    _checkOpen();
    if (epoch != _epoch) {
      throw StateError('The SSH operation has expired. Retry or reconnect.');
    }
  }

  Future<T> _deadline<T>(Future<T> work) {
    final epoch = _epoch;
    return work.timeout(
      commandTimeout,
      onTimeout: () {
        if (epoch == _epoch) {
          _epoch++;
          for (final session in _sessions.toList()) {
            session.close();
          }
        }
        throw TimeoutException('The SSH operation timed out.', commandTimeout);
      },
    );
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
      return await _deadline(action());
    } finally {
      _busy = false;
    }
  }

  Future<SSHSession> _execute(
    String command, {
    SSHPtyConfig? pty,
    bool cleanup = false,
  }) async {
    if (!cleanup) _checkOpen();
    final epoch = _epoch;
    var expired = false;
    final pending = connection.client.execute(command, pty: pty);
    pending.then((session) {
      if (expired) session.close();
    }, onError: (Object _) {});
    final session = await pending.timeout(
      cleanup ? const Duration(seconds: 3) : commandTimeout,
      onTimeout: () {
        expired = true;
        throw TimeoutException('SSH channel opening timed out.');
      },
    );
    if ((_closed && !cleanup) || epoch != _epoch) {
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
    return _preparing ??= _deadline(_prepare())
        .whenComplete(() => _preparing = null);
  }

  Future<({int? exitCode, String stdout})> _capture(String command) async {
    final session = await _execute(command);
    try {
      final results = await Future.wait([
        session.done,
        _bounded(session.stdout.cast<List<int>>())
            .transform(utf8.decoder)
            .join(),
        _bounded(session.stderr.cast<List<int>>())
            .transform(utf8.decoder)
            .transform(const LineSplitter())
            .forEach(_emit),
        session.stdin.close(),
      ], eagerError: true);
      return (exitCode: session.exitCode, stdout: results[1] as String);
    } finally {
      _sessions.remove(session);
      session.close();
    }
  }

  Future<void> _prepare() async {
    final epoch = _epoch;
    _emit('[SSH] Preparing protected server helpers.');
    if (username != 'root') {
      final sudo = await _capture('sudo -n true');
      _checkEpoch(epoch);
      if (sudo.exitCode != 0) {
        throw StateError('This account needs passwordless sudo.');
      }
    }
    _checkOpen();
    final result = await _capture(
      'umask 077; mktemp -d /tmp/ashapp.XXXXXXXXXX',
    );
    _checkEpoch(epoch);
    final created = result.stdout.trim();
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
        'amnezia_setup.py',
        'vless_manager.py',
        'security_manager.py',
        'firewall_policy.py',
        'lifecycle.py',
        'docker_setup.py',
      ]) {
        _checkOpen();
        final asset = await rootBundle.load('assets/$name');
        _checkEpoch(epoch);
        final session = await _execute('umask 077; cat > $created/$name');
        try {
          await Future.wait([
            session.done,
            _bounded(session.stdout.cast<List<int>>()).drain<void>(),
            _bounded(session.stderr.cast<List<int>>()).drain<void>(),
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
          _checkEpoch(epoch);
          if (session.exitCode != 0) {
            throw StateError('Could not upload the server files.');
          }
        } finally {
          _sessions.remove(session);
          session.close();
        }
      }
      _checkEpoch(epoch);
      // Publish readiness only after every upload has succeeded.
      _work = created;
      _emit('[SSH] Server helpers uploaded and ready.');
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
    final epoch = _epoch;
    _emit('[ACTION] Starting $action.');
    await prepare();
    _checkEpoch(epoch);
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
          final clean = line.replaceAll(RegExp(r'\x1B\[[0-?]*[ -/]*[@-~]'), '');
          // Preserve the specific Python reason over the Bash error-trap
          // summary which follows it. Neither includes stdin parameters.
          if (clean.startsWith('ERROR: ')) {
            final reason = clean.substring(7).trim();
            if (reason.isNotEmpty) {
              remoteError = reason.length > 500
                  ? 'The server reported an error. Check the activity details.'
                  : reason;
            }
          } else if (remoteError == null && clean.startsWith('[ERROR] ')) {
            remoteError = clean.substring(8).trim();
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
      ], eagerError: true);
      _checkEpoch(epoch);
      if (session.exitCode != 0) {
        _emit(
          '[ACTION] $action failed (exit code ${session.exitCode ?? 'unknown'}).',
        );
        throw StateError(
          remoteError ??
              'Server action $action failed (exit code ${session.exitCode ?? 'unknown'}). Open Server activity for details.',
        );
      }
      _emit('[ACTION] Completed $action.');
      return result;
    } finally {
      _sessions.remove(session);
      session.close();
    }
  }

  Future<void> _removeWork(String path) async {
    if (!connection.client.isClosed) {
      try {
        final session = await _execute(
          'rm -f $path/remote.sh $path/clients.py $path/amnezia_clients.py $path/amneziawg-install.sh $path/awg_setup.py $path/amnezia_setup.py $path/vless_manager.py $path/security_manager.py $path/firewall_policy.py $path/lifecycle.py $path/docker_setup.py; rmdir $path',
          cleanup: true,
        );
        try {
          await Future.wait([
            session.done,
            session.stdin.close(),
            _bounded(session.stdout.cast<List<int>>()).drain<void>(),
            _bounded(session.stderr.cast<List<int>>()).drain<void>(),
          ], eagerError: true).timeout(const Duration(seconds: 3));
        } finally {
          _sessions.remove(session);
          session.close();
        }
      } catch (_) {
        /* The connection may already be lost. */
      }
    }
  }

  Future<void> close() => _closing ??= _close();

  Future<void> _close() async {
    _closed = true;
    _epoch++;
    for (final session in _sessions.toList()) {
      session.close();
    }
    final path = _work;
    _work = null;
    if (path != null) await _removeWork(path);
    await output.close();
  }
}
