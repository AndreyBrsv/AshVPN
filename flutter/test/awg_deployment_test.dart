import 'dart:convert';

import 'package:ashapp/connection_details.dart';
import 'package:ashapp/credential_vault.dart';
import 'package:ashapp/main.dart';
import 'package:ashapp/server_template.dart';
import 'package:ashapp/setup_secrets.dart';
import 'package:ashapp/setup_wizard.dart';
import 'package:ashapp/workspace_controller.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/fakes.dart';

ServerTemplate _answers({String deployment = 'host'}) => ServerTemplate(
  name: 'Shared profile',
  blockPing: false,
  disableRoot: false,
  installAwg: true,
  installSocks: false,
  awgPort: 585,
  awgDeployment: deployment,
  clientNames: ['phone'],
  createAdmin: false,
  protectSsh: false,
  configureFirewall: false,
);

class _RecordingController extends WorkspaceController {
  _RecordingController(Harness h)
    : super(
        profilesRepository: h.profiles,
        templatesRepository: h.templates,
        vault: CredentialVault(h.store),
        connector: h.connect,
        backendFactory: h.createBackend,
      );

  ServerTemplate? submitted;

  @override
  Future<bool> provision(
    ServerTemplate answers,
    SetupSecrets secrets, {
    String? resumeRunId,
  }) async {
    submitted = answers;
    return true;
  }
}

const _login = ConnectionDetails(
  host: '203.0.113.10',
  port: 22,
  user: 'root',
  password: 'synthetic-login-placeholder',
);

Future<void> _continue(WidgetTester tester, [int times = 1]) async {
  for (var step = 0; step < times; step++) {
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();
  }
}

void main() {
  test(
    'new templates default to shared while saved host choices stay host',
    () {
      final fresh = ServerTemplate(
        name: 'New server',
        blockPing: false,
        disableRoot: false,
        installAwg: true,
        installSocks: false,
        awgPort: 585,
        clientNames: [],
      );
      expect(fresh.awgDeployment, 'amnezia');
      expect(ServerTemplate.fromJson(fresh.toJson()).awgDeployment, 'amnezia');
      expect(
        ServerTemplate.fromJson(_answers().toJson()).awgDeployment,
        'host',
      );
    },
  );

  test(
    'legacy templates without a deployment retain their host installation',
    () {
      final legacy = _answers().toJson()..remove('awg_deployment');
      final loaded = ServerTemplate.fromJson(legacy);
      expect(loaded.awgDeployment, 'host');
      expect(loaded.toJson()['awg_deployment'], 'host');
    },
  );

  test(
    'shared deployment round-trips and survives protected-answer revisions',
    () {
      final shared = _answers(deployment: 'amnezia');
      final loaded = ServerTemplate.fromJson(jsonDecode(jsonEncode(shared)));
      expect(loaded.awgDeployment, 'amnezia');
      expect(loaded.toJson(), shared.toJson());
      expect(
        loaded
            .withCredentialsRef('0123456789abcdef0123456789abcdef')
            .awgDeployment,
        'amnezia',
      );
      expect(loaded.clientNames, ['phone']);
      expect(loaded.installVless, isFalse);
      expect(loaded.toJson().keys, isNot(contains('password')));
    },
  );

  test(
    'unsupported deployment modes are rejected rather than changed silently',
    () {
      for (final invalid in [
        null,
        1,
        true,
        '',
        'docker',
        'HOST',
        'amnezia-go',
      ]) {
        expect(
          () => ServerTemplate.fromJson({
            ..._answers().toJson(),
            'awg_deployment': invalid,
          }),
          throwsFormatException,
          reason: 'Invalid deployment: $invalid',
        );
      }
      expect(() => _answers(deployment: 'unknown'), throwsFormatException);
    },
  );

  testWidgets(
    'shared template selection wraps and survives installation toggle',
    (tester) async {
      tester.view.physicalSize = const Size(420, 760);
      tester.view.devicePixelRatio = 1;
      tester.platformDispatcher.textScaleFactorTestValue = 1.5;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      final h = Harness();
      addTearDown(h.vm.dispose);
      await tester.pumpWidget(
        AshappApp(
          home: SetupWizard(
            controller: h.vm,
            editTemplate: true,
            initial: _answers(deployment: 'amnezia'),
          ),
        ),
      );
      await _continue(tester, 3);
      expect(find.text('AmneziaWG deployment'), findsOneWidget);
      expect(
        tester
            .widget<RadioGroup<String>>(find.byType(RadioGroup<String>))
            .groupValue,
        'amnezia',
      );
      for (final label in [
        'Host kernel (Ashapp management)',
        'Shared kernel (Ashapp + AmneziaVPN)',
      ]) {
        expect(
          tester
              .renderObject<RenderParagraph>(find.text(label))
              .didExceedMaxLines,
          isFalse,
        );
      }
      final install = find.widgetWithText(SwitchListTile, 'Install AmneziaWG');
      await tester.ensureVisible(install);
      await tester.tap(install);
      await tester.pumpAndSettle();
      expect(find.byType(RadioGroup<String>), findsNothing);
      await tester.tap(install);
      await tester.pumpAndSettle();
      expect(
        tester
            .widget<RadioGroup<String>>(find.byType(RadioGroup<String>))
            .groupValue,
        'amnezia',
      );
      await _continue(tester, 2);
      expect(
        find.textContaining(
          'Install AmneziaWG kernel: Yes · Shared kernel (Ashapp + AmneziaVPN)',
        ),
        findsOneWidget,
      );
      await tester.tap(find.widgetWithText(FilledButton, 'Save template'));
      await tester.pumpAndSettle();
      expect(h.vm.templates.single.awgDeployment, 'amnezia');
      expect(h.templates.records.single.awgDeployment, 'amnezia');
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('manual setup defaults to and submits shared deployment', (
    tester,
  ) async {
    final h = Harness();
    final vm = _RecordingController(h);
    addTearDown(vm.dispose);
    await vm.connect(_login, (_, _) async => true);
    await tester.pumpWidget(
      AshappApp(home: SetupWizard(controller: vm, useConnected: true)),
    );
    await tester.pumpAndSettle();
    await _continue(tester, 3);
    expect(
      tester
          .widget<RadioGroup<String>>(find.byType(RadioGroup<String>))
          .groupValue,
      'amnezia',
    );
    await _continue(tester, 2);
    expect(
      find.textContaining(
        'Install AmneziaWG kernel: Yes · Shared kernel (Ashapp + AmneziaVPN)',
      ),
      findsOneWidget,
    );
    await tester.tap(find.widgetWithText(FilledButton, 'Run setup'));
    await tester.pumpAndSettle();
    expect(vm.submitted?.awgDeployment, 'amnezia');
    expect(vm.submitted?.awgPort, 585);
    expect(vm.submitted?.installAwg, isTrue);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
