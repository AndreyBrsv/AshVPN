import 'dart:io';

import 'package:ashapp/connection_details.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

const containerId =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const replacementId =
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

Future<void> connectProxy(
  Harness harness, {
  String host = '203.0.113.10',
}) async {
  final server = harness.servers.putIfAbsent(host, FakeServer.new);
  server.state.addAll({
    'socks5': true,
    'socks5_configured': true,
    'socks5_port': server.socksPort,
    'socks5_access': 'private',
    'socks5_container_id': containerId,
    'socks5_source': 'amnezia-socks5proxy',
  });
  expect(
    await harness.vm.connect(
      ConnectionDetails(
        host: host,
        port: 22,
        user: 'alice',
        password: 'synthetic-ssh-cache-placeholder',
      ),
      (_, _) async => true,
    ),
    isTrue,
  );
}

void main() {
  test(
    'refresh forgets externally changed credentials without refetching secrets',
    () async {
      final first = Harness(), second = Harness();
      addTearDown(first.vm.dispose);
      addTearDown(second.vm.dispose);
      await connectProxy(first);
      await connectProxy(second, host: '203.0.113.20');
      expect(await first.vm.readSocks(), isTrue);
      expect(await second.vm.readSocks(), isTrue);
      final otherDetails = second.vm.socks;
      first.server.calls.clear();
      first.server.socksUser = 'changed_proxy';
      first.server.socksPassword = 'synthetic_changed_placeholder';
      expect(await first.vm.refresh(), isTrue);
      expect(first.vm.socks, isNull);
      expect(
        first.server.calls.where((call) => call.$1 == 'socks-info'),
        isEmpty,
      );
      expect(second.vm.socks, same(otherDetails));
      expect(await first.vm.readSocks(), isTrue);
      expect(first.vm.socks!.user, 'changed_proxy');
      expect(first.vm.socks!.password, 'synthetic_changed_placeholder');
    },
  );

  test(
    'unchanged verified target retains its tunnel but clears displayed secrets',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connectProxy(h);
      expect(await h.vm.startSocksTunnel(), isTrue);
      final tunnel = h.vm.socksTunnel!;
      addTearDown(tunnel.close);
      final localPort = tunnel.port;
      expect(await h.vm.refresh(), isTrue);
      expect(h.vm.socksTunnel, same(tunnel));
      expect(h.vm.socks, isNull);
      expect(await h.vm.readSocks(), isTrue);
      expect(h.vm.socks!.port, localPort);
      expect(h.vm.server['socks5_port'], 1080);
      expect(h.vm.server['socks5_source'], 'amnezia-socks5proxy');
    },
  );

  for (final (label, changes) in [
    ('replacement', {'socks5_container_id': replacementId}),
    ('new port', {'socks5_port': 1081}),
    ('public exposure', {'socks5_access': 'public'}),
    ('removal', {'socks5': false, 'socks5_configured': false}),
    ('unknown identity', {'socks5_container_id': null}),
  ]) {
    test(
      'status $label closes the old tunnel and clears cached access',
      () async {
        final h = Harness();
        addTearDown(h.vm.dispose);
        await connectProxy(h);
        expect(await h.vm.startSocksTunnel(), isTrue);
        final tunnel = h.vm.socksTunnel!;
        addTearDown(tunnel.close);
        final port = tunnel.port;
        h.server.state.addAll(changes);
        expect(await h.vm.refresh(), isTrue);
        expect(h.vm.socksTunnel, isNull);
        expect(h.vm.socks, isNull);
        await expectLater(
          Socket.connect('127.0.0.1', port),
          throwsA(isA<SocketException>()),
        );
      },
    );
  }

  test(
    'inspection failure discards old access and closes its tunnel',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connectProxy(h);
      expect(await h.vm.startSocksTunnel(), isTrue);
      final tunnel = h.vm.socksTunnel!;
      addTearDown(tunnel.close);
      h.server.failAction = 'status';
      expect(await h.vm.refresh(), isTrue);
      expect(h.vm.socks, isNull);
      expect(h.vm.socksTunnel, isNull);
      expect(h.vm.inspectionWarnings, isNotEmpty);
    },
  );

  test('explicit reload uses the actual server port and retires an outdated tunnel', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connectProxy(h);
    expect(await h.vm.startSocksTunnel(), isTrue);
    final tunnel = h.vm.socksTunnel!;
    addTearDown(tunnel.close);
    h.server.socksPort = 1081;
    expect(await h.vm.readSocks(), isTrue);
    expect(h.vm.socksTunnel, isNull);
    expect(h.vm.server['socks5_port'], 1081);
    expect(h.vm.socks!.port, 1081);
    h.server.failAction = 'socks-info';
    expect(await h.vm.readSocks(), isFalse);
    expect(h.vm.socks, isNull);
  });

  test(
    'full diagnostics invalidate credentials and retire changed targets',
    () async {
      final h = Harness();
      addTearDown(h.vm.dispose);
      await connectProxy(h);
      expect(await h.vm.startSocksTunnel(), isTrue);
      final tunnel = h.vm.socksTunnel!;
      addTearDown(tunnel.close);
      h.server.state['socks5_container_id'] = replacementId;
      expect(await h.vm.diagnoseSecurity(), isTrue);
      expect(h.vm.socks, isNull);
      expect(h.vm.socksTunnel, isNull);
    },
  );

  test('successful replacement returns freshly verified connection data after refresh', () async {
    final h = Harness();
    addTearDown(h.vm.dispose);
    await connectProxy(h);
    expect(
      await h.vm.configureSocks(
        1081,
        'new_proxy',
        'synthetic_new_placeholder',
        replace: true,
      ),
      isTrue,
    );
    expect(h.vm.socks!.port, 1081);
    expect(h.vm.socks!.user, 'new_proxy');
    expect(h.vm.socks!.password, 'synthetic_new_placeholder');
    expect(h.vm.server['socks5_port'], 1081);
  });
}
