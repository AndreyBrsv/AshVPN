import 'dart:async';
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';

/// A loopback-only local forward; proxy authentication is still performed by 3proxy.
class SocksTunnel {
  SocksTunnel._(this.listener, this.client, this.remotePort) {
    _subscription = listener.listen(_accept, onError: (_) => close());
    unawaited(
      client.done.then(
        (_) => close(),
        onError: (Object _, StackTrace _) => close(),
      ),
    );
  }
  final ServerSocket listener;
  final SSHClient client;
  final int remotePort;
  final _sockets = <Socket>{};
  final _channels = <SSHForwardChannel>{};
  StreamSubscription<Socket>? _subscription;
  bool _closed = false;
  int get port => listener.port;

  static Future<SocksTunnel> start(SSHClient client, int remotePort) async {
    final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    return SocksTunnel._(listener, client, remotePort);
  }

  Future<void> _accept(Socket socket) async {
    if (_closed || _sockets.length >= 32) {
      socket.destroy();
      return;
    }
    _sockets.add(socket);
    SSHForwardChannel? channel;
    try {
      channel = await client
          .forwardLocal('127.0.0.1', remotePort)
          .timeout(const Duration(seconds: 15));
      if (_closed) return;
      _channels.add(channel);
      await Future.wait([
        socket
            .timeout(const Duration(minutes: 5))
            .cast<List<int>>()
            .pipe(channel.sink),
        channel.stream.cast<List<int>>().pipe(socket),
      ], eagerError: true);
    } catch (_) {
      /* A single failed tunnel must not affect the management session. */
    } finally {
      socket.destroy();
      channel?.destroy();
      _sockets.remove(socket);
      _channels.remove(channel);
    }
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _subscription?.cancel();
    await listener.close();
    for (final socket in _sockets) {
      socket.destroy();
    }
    for (final channel in _channels) {
      channel.destroy();
    }
  }
}
