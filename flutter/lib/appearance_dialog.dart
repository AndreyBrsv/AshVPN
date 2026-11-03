import 'package:flutter/material.dart';

import 'appearance.dart';

class AppearanceDialog extends StatelessWidget {
  const AppearanceDialog({super.key, required this.controller});
  final AppearanceController controller;

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: controller,
    builder: (context, _) => AlertDialog(
      title: const Text('Appearance'),
      scrollable: true,
      content: SizedBox(
        width: 360,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Choose a theme for all your servers. '
              'Your choice is saved on this computer.',
            ),
            const SizedBox(height: 16),
            RadioGroup<ThemeMode>(
              groupValue: controller.mode,
              onChanged: (mode) {
                if (mode != null && !controller.saving) controller.select(mode);
              },
              child: Column(
                children: [
                  for (final option in const [
                    (ThemeMode.system, 'System', 'Follow your device settings'),
                    (ThemeMode.light, 'Light', null),
                    (ThemeMode.dark, 'Dark', null),
                  ])
                    RadioListTile<ThemeMode>(
                      value: option.$1,
                      title: Text(option.$2),
                      subtitle: option.$3 == null ? null : Text(option.$3!),
                      enabled: !controller.saving,
                      contentPadding: EdgeInsets.zero,
                    ),
                ],
              ),
            ),
            if (controller.saving) const LinearProgressIndicator(),
            if (controller.error case final error?)
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: Text(
                  error,
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Done'),
        ),
      ],
    ),
  );
}
