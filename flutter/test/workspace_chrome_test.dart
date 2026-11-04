import 'package:ashapp/workspace_shell.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets(
    'native title is not duplicated; toolbar actions remain accessible',
    (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: WorkspaceShell(
            selectedIndex: 0,
            onDestinationSelected: (_) {},
            actions: [
              IconButton(
                onPressed: () {},
                tooltip: 'Check for updates',
                icon: const Icon(Icons.update),
              ),
            ],
            child: const Text('Server content'),
          ),
        ),
      );
      expect(find.text('Ashapp'), findsNothing);
      expect(find.byType(Image), findsNothing);
      expect(find.byTooltip('Check for updates'), findsOneWidget);
      expect(find.text('Server content'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );
}
