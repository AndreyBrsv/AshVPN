import 'package:flutter/material.dart';

import 'ui_components.dart';
import 'workspace_controller.dart';

/// Server evidence stays attached to the controller that requested it.
class ServerInstallationPanel extends StatefulWidget {
  const ServerInstallationPanel({
    super.key,
    required this.controller,
    required this.onResume,
  });
  final WorkspaceController controller;
  final VoidCallback onResume;

  @override
  State<ServerInstallationPanel> createState() =>
      _ServerInstallationPanelState();
}

class _ServerInstallationPanelState extends State<ServerInstallationPanel> {
  bool reviewing = false;

  Future<void> reset() async {
    final target = widget.controller;
    setState(() => reviewing = true);
    try {
      final plan = await target.previewReset();
      if (plan == null || !mounted) return;
      final components = plan['components'] as Map;
      final policy = plan['security'] as Map;
      final rows = components['components'] as List? ?? [];
      if (!await confirmAction(
        context,
        'Remove Ashapp server configuration?',
        '${plan['endpoint']}\n\n'
            '${rows.map((r) => '${r['label']}: ${r['removable'] == true ? 'Remove' : 'Keep'}${r['reason'] == null ? '' : ' — ${r['reason']}'}').join('\n')}\n\n'
            '${components['notice'] ?? ''}\n${policy['notice'] ?? ''}\n\n'
            'Removing VPNs revokes their client access. Original owned SSH, firewall and ping settings are restored when a verified baseline is available. '
            'Administrator accounts and their current passwords remain. Packages and external installations remain. '
            'This does not reinstall the operating system. Keep this SSH session open.',
        action: 'Remove configuration',
      )) {
        return;
      }
      await target.resetServer(plan);
    } finally {
      if (mounted) setState(() => reviewing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final vm = widget.controller;
    final state = vm.installation;
    final steps = state['steps'] as Map? ?? {};
    final events = state['events'] as List? ?? [];
    return SectionCard(
      title: 'Installation and diagnostics',
      subtitle: state.isEmpty || state['status'] == 'idle'
          ? 'No recorded Ashapp setup. Inspect existing services before making changes.'
          : 'Server journal: ${state['status']}. Actual configuration is checked separately.',
      children: [
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            OutlinedButton.icon(
              onPressed: vm.busy || reviewing ? null : vm.diagnoseSecurity,
              icon: const Icon(Icons.fact_check_outlined),
              label: const Text('Run full diagnostics'),
            ),
            if (vm.canResumeSetup)
              FilledButton(
                onPressed: vm.busy || reviewing ? null : widget.onResume,
                child: const Text('Resume interrupted setup'),
              ),
          ],
        ),
        for (final warning in vm.inspectionWarnings)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: Text(
              warning,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        if (steps.isNotEmpty)
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            title: const Text('Recorded setup steps'),
            children: [
              for (final entry in steps.entries)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(
                    (entry.value as Map)['state'] == 'done'
                        ? Icons.check_circle_outline
                        : Icons.pending_outlined,
                  ),
                  title: Text(entry.key.toString()),
                  subtitle: Text('${entry.value['state']}'),
                ),
            ],
          ),
        if (events.isNotEmpty)
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            title: const Text('Recent server activity'),
            subtitle: const Text(
              'Action names and results only. No passwords, keys or command input.',
            ),
            children: [
              for (final event in events.reversed.take(20))
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(
                    '${event['step'] ?? event['action'] ?? 'Setup'} · ${event['state']}',
                  ),
                  subtitle: Text('${event['time']}'),
                ),
            ],
          ),
        for (final check in vm.diagnosticChecks)
          ListTile(
            contentPadding: EdgeInsets.zero,
            leading: Icon(
              switch (check['status']) {
                'pass' => Icons.check_circle_outline,
                'fail' => Icons.error_outline,
                'warn' => Icons.warning_amber_outlined,
                _ => Icons.help_outline,
              },
              color: check['status'] == 'fail'
                  ? Theme.of(context).colorScheme.error
                  : null,
            ),
            title: Text('${check['id']} · ${check['status']}'),
            subtitle: Text('${check['detail']}'),
          ),
        const Divider(height: 32),
        const Text('Remove server configuration'),
        const SizedBox(height: 8),
        const Text(
          'Remove only services and settings with verified Ashapp ownership. Keep administrator accounts, passwords and the operating system.',
        ),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          onPressed: vm.busy || reviewing ? null : reset,
          icon: const Icon(Icons.delete_outline),
          label: Text(reviewing ? 'Inspecting reset…' : 'Review server reset'),
        ),
      ],
    );
  }
}
