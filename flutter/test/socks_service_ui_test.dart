import 'package:ashapp/connection_details.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/socks_tunnel.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

class DisplayTunnel extends Fake implements SocksTunnel {
  @override
  int get port => 10080;
  @override
  Future<void> close() async {}
}

void main() {
  for (final access in ['public', 'private']) {
    testWidgets(
      'SOCKS $access shows one server service and its real endpoint',
      (tester) async {
        tester.view.physicalSize = const Size(420, 600);
        tester.view.devicePixelRatio = 1;
        tester.platformDispatcher.textScaleFactorTestValue = 1.5;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
        final h = Harness();
        addTearDown(h.vm.dispose);
        h.server.state.addAll({
          'socks5': true,
          'socks5_configured': true,
          'socks5_port': 2080,
          'socks5_access': access,
          'socks5_source': 'amnezia-socks5proxy',
          'socks5_container_id': List.filled(64, 'a').join(),
          'socks5_owned': false,
        });
        await h.vm.connect(
          const ConnectionDetails(
            host: '203.0.113.10',
            port: 22,
            user: 'alice',
            password: 'synthetic-ui-placeholder',
          ),
          (_, _) async => true,
        );
        if (access == 'private') h.vm.socksTunnel = DisplayTunnel();
        await tester.pumpWidget(AshappApp(home: HomePage(controller: h.vm)));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Manage').last);
        await tester.pumpAndSettle();
        expect(
          find.text('Server service: amnezia-socks5proxy'),
          findsOneWidget,
        );
        expect(find.text('Manage SOCKS5 proxy'), findsOneWidget);
        expect(find.text('Install SOCKS5'), findsNothing);
        expect(
          find.text(
            access == 'private'
                ? 'Server endpoint: 127.0.0.1:2080 (on the VPS only)'
                : 'Server endpoint: 203.0.113.10:2080',
          ),
          findsOneWidget,
        );
        expect(
          find.text('Local SSH tunnel to this proxy: 127.0.0.1:10080'),
          access == 'private' ? findsOneWidget : findsNothing,
        );
        expect(
          h.server.calls.where((call) => call.$1 == 'socks-install'),
          isEmpty,
        );
        expect(tester.takeException(), isNull);
      },
    );
  }
}
