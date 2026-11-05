import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:ashapp/remote_backend.dart';
import 'package:ashapp/ssh_connection.dart';
import 'package:dartssh2/dartssh2.dart';
import 'package:flutter_test/flutter_test.dart';

class TestSession extends Fake implements SSHSession {
  TestSession({this.code = 0, String text = '', String error = '', this.gate})
    : bytes = Uint8List.fromList(utf8.encode(text)),
      errorBytes = Uint8List.fromList(utf8.encode(error)) {
    input.stream.listen(
      (_) {},
      onDone: () {
        if (gate == null && !finished.isCompleted) finished.complete();
      },
    );
  }
  final int code;
  final Uint8List bytes;
  final Uint8List errorBytes;
  final Completer<void>? gate;
  final finished = Completer<void>();
  final input = StreamController<Uint8List>();
  @override
  StreamSink<Uint8List> get stdin => input.sink;
  @override
  Stream<Uint8List> get stdout => Stream.value(bytes);
  @override
  Stream<Uint8List> get stderr => Stream.value(errorBytes);
  @override
  Future<void> get done => gate?.future ?? finished.future;
  @override
  int get exitCode => code;
  @override
  void close() {
    if (!finished.isCompleted) finished.complete();
    if (gate != null && !gate!.isCompleted) gate!.complete();
    input.close();
  }
}

class TestClient extends Fake implements SSHClient {
  final commands = <String>[];
  int directories = 0;
  bool failNextUpload = false;
  bool denySudo = false;
  bool malformedOutput = false;
  bool configured = false;
  bool excessiveOutput = false;
  String? commandError;
  Completer<void>? commandGate;
  Completer<void>? preparationGate;
  String? stalledCommand;
  Completer<SSHSession>? openingGate;
  final sessions = <TestSession>[];
  @override
  bool get isClosed => false;

  @override
  Future<SSHSession> execute(
    String command, {
    SSHPtyConfig? pty,
    SSHX11Config? x11,
    Map<String, String>? environment,
  }) async {
    commands.add(command);
    if (openingGate != null && command == stalledCommand) {
      return openingGate!.future;
    }
    if (command == 'sudo -n true' || command.contains('mktemp')) {
      final session = TestSession(
        code: command == 'sudo -n true' && denySudo ? 1 : 0,
        gate: command == stalledCommand ? preparationGate : null,
        text: excessiveOutput
            ? List.filled(8 * 1024 * 1024 + 1, 'x').join()
            : command.contains('mktemp')
            ? '/tmp/ashapp.test${++directories}\n'
            : '',
      );
      sessions.add(session);
      return session;
    }
    if (command.startsWith('rm -f')) return TestSession();
    if (command.contains('cat >')) {
      final fail = failNextUpload;
      failNextUpload = false;
      final session = TestSession(
        code: fail ? 1 : 0,
        gate: stalledCommand == 'upload' ? preparationGate : null,
      );
      sessions.add(session);
      return session;
    }
    final session = TestSession(
      gate: commandGate,
      code: commandError == null ? 0 : 1,
      error: commandError == null ? '' : 'ERROR: $commandError\n',
      text: excessiveOutput
          ? List.filled(8 * 1024 * 1024 + 1, 'x').join()
          : malformedOutput
          ? 'ASHAPP_JSON:invalid\n'
          : 'ASHAPP_JSON:${jsonEncode({'ok': true, if (configured) 'awg_configured': true})}\n',
    );
    if (pty != null) session.finished.complete();
    return session;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  for (final stage in [
    'sudo -n true',
    'umask 077; mktemp -d /tmp/ashapp.XXXXXXXXXX',
    'upload',
  ]) {
    test(
      'timeout covers preparation at $stage and permits a clean retry',
      () async {
        final client = TestClient()
          ..stalledCommand = stage
          ..preparationGate = Completer<void>();
        final backend = RemoteBackend(
          SshConnection.fromClient(client),
          'friend',
          commandTimeout: const Duration(milliseconds: 80),
        );
        addTearDown(backend.close);
        await expectLater(
          backend.run('status'),
          throwsA(isA<TimeoutException>()),
        );
        expect(client.preparationGate!.isCompleted, isTrue);
        client.stalledCommand = null;
        // Let the cancelled preparation unwind before retrying.
        await Future<void>.delayed(const Duration(milliseconds: 10));
        expect(await backend.run('status'), {'ok': true});
      },
    );
  }
  test(
    'late channel opening after a timeout is closed without running an action',
    () async {
      final client = TestClient()
        ..stalledCommand = 'sudo -n true'
        ..openingGate = Completer<SSHSession>();
      final backend = RemoteBackend(
        SshConnection.fromClient(client),
        'friend',
        commandTimeout: const Duration(milliseconds: 30),
      );
      addTearDown(backend.close);
      await expectLater(
        backend.run('status'),
        throwsA(isA<TimeoutException>()),
      );
      final late = TestSession(gate: Completer<void>());
      client.openingGate!.complete(late);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(late.finished.isCompleted, isTrue);
      expect(
        client.commands.where((s) => s.contains('remote.sh status')),
        isEmpty,
      );
    },
  );
  test('client validation errors remain actionable instead of a generic action failure', () async {
    final client = TestClient()
      ..commandError = 'The private configuration does not match this client.';
    final backend = RemoteBackend(SshConnection.fromClient(client), 'root');
    addTearDown(backend.close);
    await expectLater(
      backend.run('import-client'),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          client.commandError,
        ),
      ),
    );
  });
  test(
    'excessive unbroken server output is rejected before line buffering',
    () async {
      final backend = RemoteBackend(
        SshConnection.fromClient(TestClient()..excessiveOutput = true),
        'root',
      );
      addTearDown(backend.close);
      await expectLater(backend.run('status'), throwsStateError);
    },
  );

  test('a hung command times out, closes its channel and releases the action guard', () async {
    final client = TestClient()..commandGate = Completer<void>();
    final backend = RemoteBackend(
      SshConnection.fromClient(client),
      'root',
      commandTimeout: const Duration(milliseconds: 20),
    );
    addTearDown(backend.close);
    await expectLater(backend.run('status'), throwsA(isA<TimeoutException>()));
    expect(client.commandGate!.isCompleted, isTrue);
    client.commandGate = null;
    expect(await backend.run('status'), {'ok': true});
  });

  test(
    'failed upload is cleaned up and preparation is retried in full',
    () async {
      final client = TestClient()..failNextUpload = true;
      final backend = RemoteBackend(SshConnection.fromClient(client), 'root');
      addTearDown(backend.close);
      await expectLater(backend.run('preflight'), throwsStateError);
      expect(await backend.run('preflight'), {'ok': true});
      expect(client.directories, 2);
      expect(
        client.commands.where((s) => s.startsWith('rm -f /tmp/ashapp.test1')),
        hasLength(1),
      );
      expect(
        client.commands.where(
          (s) => s.startsWith('umask 077; cat > /tmp/ashapp.test2/'),
        ),
        hasLength(8),
      );
    },
  );

  test(
    'concurrent preparation shares uploads and operations cannot overlap',
    () async {
      final client = TestClient();
      final backend = RemoteBackend(SshConnection.fromClient(client), 'root');
      addTearDown(backend.close);
      await Future.wait([backend.prepare(), backend.prepare()]);
      expect(client.directories, 1);
      client.commandGate = Completer<void>();
      final pending = backend.run('clients');
      await expectLater(backend.run('add-client', ['phone']), throwsStateError);
      client.commandGate!.complete();
      await pending;
    },
  );

  test('sudo failure prevents uploads and privileged actions', () async {
    final client = TestClient()..denySudo = true;
    final backend = RemoteBackend(SshConnection.fromClient(client), 'friend');
    addTearDown(backend.close);
    await expectLater(backend.run('preflight'), throwsStateError);
    expect(client.commands, ['sudo -n true']);
  });

  test(
    'sudo preserves SSH connection context for Match address checks',
    () async {
      final client = TestClient();
      final backend = RemoteBackend(SshConnection.fromClient(client), 'friend');
      addTearDown(backend.close);
      await backend.run('ssh-config', ['friend', 'no']);
      expect(
        client.commands.last,
        startsWith('sudo -n env "SSH_CONNECTION=\$SSH_CONNECTION" bash '),
      );
      expect(client.commands.last, endsWith('remote.sh ssh-config'));
    },
  );

  test(
    'malformed server output fails and the backend can be closed twice',
    () async {
      final client = TestClient()..malformedOutput = true;
      final backend = RemoteBackend(SshConnection.fromClient(client), 'root');
      await expectLater(backend.run('status'), throwsFormatException);
      await backend.close();
      await backend.close();
      await expectLater(backend.run('status'), throwsStateError);
    },
  );

  test('closing an active action closes sessions without writing to a closed stream', () async {
    final client = TestClient();
    final backend = RemoteBackend(SshConnection.fromClient(client), 'root');
    await backend.prepare();
    client.commandGate = Completer<void>();
    final pending = expectLater(backend.run('clients'), throwsStateError);
    await Future<void>.delayed(Duration.zero);
    await backend.close();
    await pending;
  });
}
