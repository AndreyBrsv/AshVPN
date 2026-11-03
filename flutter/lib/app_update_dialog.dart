import 'package:flutter/material.dart';

import 'app_update.dart';
import 'ui_components.dart';

class AppUpdateDialog extends StatelessWidget {
  const AppUpdateDialog({
    super.key,
    required this.controller,
    required this.workspace,
    required this.canInstall,
  });
  final AppUpdateController controller;
  final Listenable workspace;
  final bool Function() canInstall;

  Future<void> _install(BuildContext context) async {
    final approved = await confirmAction(
      context,
      'Install Ashapp ${controller.release!.version}?',
      'Ashapp will close and disconnect all SSH sessions. Complete the system installer, then reopen the app. '
          'Your saved servers, templates and protected passwords stay on this computer. '
          'Windows installs into your user Programs folder; macOS installs into Applications.',
      action: 'Open installer',
    );
    if (approved) await controller.install(canInstall: canInstall);
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: Listenable.merge([controller, workspace]),
    builder: (context, _) {
      final vm = controller;
      final downloading = vm.phase == UpdatePhase.downloading;
      final checking = vm.phase == UpdatePhase.checking;
      final ready = vm.phase == UpdatePhase.ready;
      return AlertDialog(
        title: const Text('App updates'),
        content: SizedBox(
          width: 520,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  vm.platform == null
                      ? 'Ashapp'
                      : 'Ashapp ${vm.platform!.version}',
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                const SizedBox(height: 8),
                const Text('Stable releases from AndreyBrsv/Ashapp on GitHub.'),
                const SizedBox(height: 16),
                SwitchListTile.adaptive(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Check automatically'),
                  subtitle: const Text(
                    'Once a day. Download and installation always require your approval.',
                  ),
                  value: vm.automatic,
                  onChanged: vm.locksWorkspace ? null : vm.setAutomatic,
                ),
                if (vm.lastChecked != null)
                  Text(
                    'Last checked: ${MaterialLocalizations.of(context).formatMediumDate(vm.lastChecked!.toLocal())} ${MaterialLocalizations.of(context).formatTimeOfDay(TimeOfDay.fromDateTime(vm.lastChecked!.toLocal()))}',
                  ),
                const SizedBox(height: 16),
                if (checking ||
                    downloading ||
                    vm.phase == UpdatePhase.installing) ...[
                  LinearProgressIndicator(
                    value: downloading ? vm.progress : null,
                    semanticsLabel: downloading
                        ? 'Downloading update'
                        : 'Checking or installing update',
                  ),
                  const SizedBox(height: 8),
                  Text(
                    downloading
                        ? 'Downloading… ${(vm.progress * 100).round()}%'
                        : checking
                        ? 'Checking GitHub…'
                        : 'Complete the system installer, then reopen Ashapp.',
                  ),
                  const SizedBox(height: 16),
                ],
                if (vm.notice.isNotEmpty)
                  Semantics(liveRegion: true, child: Text(vm.notice)),
                if (vm.error.isNotEmpty)
                  Semantics(
                    liveRegion: true,
                    child: Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: Text(
                        vm.error,
                        style: TextStyle(
                          color: Theme.of(context).colorScheme.error,
                        ),
                      ),
                    ),
                  ),
                if (vm.release != null) ...[
                  const SizedBox(height: 24),
                  Text(
                    'Available: ${vm.release!.version}',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  if (vm.release!.notes.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    SelectableText(vm.release!.notes),
                  ],
                ],
                if (ready && !canInstall()) ...[
                  const SizedBox(height: 16),
                  const Text(
                    'Finish tasks on all servers and close setup/connection dialogs before installing.',
                  ),
                ],
                const SizedBox(height: 24),
                const Text(
                  'Downloads are checked against GitHub SHA-256 digests and the release checksum file. '
                  'Packages are currently unsigned by Microsoft/Apple; system confirmation may be required.',
                ),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
          if (downloading)
            OutlinedButton(
              onPressed: vm.cancelDownload,
              child: const Text('Cancel download'),
            ),
          if (!vm.working && vm.prepared == null)
            OutlinedButton(onPressed: vm.check, child: const Text('Check now')),
          if (vm.release != null && !vm.working && vm.prepared == null)
            FilledButton.icon(
              onPressed: vm.download,
              icon: const Icon(Icons.download_outlined),
              label: const Text('Download update'),
            ),
          if (ready)
            TextButton(
              onPressed: vm.discardDownload,
              child: const Text('Remove download'),
            ),
          if (ready)
            FilledButton.icon(
              onPressed: canInstall() ? () => _install(context) : null,
              icon: const Icon(Icons.system_update_outlined),
              label: const Text('Install update…'),
            ),
        ],
      );
    },
  );
}
