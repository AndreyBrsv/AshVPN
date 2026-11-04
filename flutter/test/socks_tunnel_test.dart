import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:ashapp/socks_tunnel.dart';
import 'package:dartssh2/dartssh2.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

class EchoChannel extends Fake implements SSHForwardChannel {
  EchoChannel() {
    input.stream.listen(
      (bytes) => output.add(Uint8List.fromList(bytes)),
      onDone: destroy,
    );
  }
  final input = StreamController<List<int>>();
  final output = StreamController<Uint8List>();
  bool destroyed = false;
  @override
  StreamSink<List<int>> get sink => input.sink;
  @override
  Stream<Uint8List> get stream => output.stream;
  @override
  void destroy() {
    if (!destroyed) {
      destroyed = true;
      unawaited(output.close());
    }
  }
}

class TunnelClient extends FakeClient {
  final calls = <(String, int)>[];
  final channels = <EchoChannel>[];
  @override
  Future<SSHForwardChannel> forwardLocal(
    String remoteHost,
    int remotePort, {
    String localHost = 'localhost',
    int localPort = 0,
  }) async {
    calls.add((remoteHost, remotePort));
    final channel = EchoChannel();
    channels.add(channel);
    return channel;
  }
}

void main() {
  test('private proxy forwards bytes to server loopback and closes local listeners', () async {
    final client = TunnelClient();
    final tunnel = await SocksTunnel.start(client, 1080);
    addTearDown(tunnel.close);
    addTearDown(client.close);
    expect(tunnel.listener.address, InternetAddress.loopbackIPv4);
    final socket = await Socket.connect('127.0.0.1', tunnel.port);
    addTearDown(socket.destroy);
    final reply = socket.first.timeout(const Duration(seconds: 5));
    socket.add([5, 1, 2]);
    await socket.flush();
    expect(await reply, [5, 1, 2]);
    expect(client.calls, [('127.0.0.1', 1080)]);
    final port = tunnel.port;
    await tunnel.close();
    await expectLater(
      Socket.connect('127.0.0.1', port),
      throwsA(isA<SocketException>()),
    );
  });
}
