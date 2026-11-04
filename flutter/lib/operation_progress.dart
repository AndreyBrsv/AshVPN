import 'package:flutter/material.dart';

import 'workspace_controller.dart';

class OperationProgress extends StatelessWidget {
  const OperationProgress({super.key, required this.controller});
  final WorkspaceController controller;

  @override
  Widget build(BuildContext context) {
    final tasks = controller.tasks;
    if (!controller.busy && tasks.isEmpty) return const SizedBox.shrink();
    final done = tasks.where((t) => t.state == TaskState.done).length;
    final running = tasks
        .where((t) => t.state == TaskState.running)
        .firstOrNull;
    final failed = tasks.any((t) => t.state == TaskState.failed);
    final seconds = controller.elapsed.inSeconds;
    return Semantics(
      liveRegion: true,
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              running?.label ??
                  (failed ? 'Stopped after an error' : controller.message),
            ),
            const SizedBox(height: 8),
            LinearProgressIndicator(
              value: tasks.isEmpty ? null : done / tasks.length,
            ),
            const SizedBox(height: 8),
            Text(
              '${tasks.isEmpty ? 'Working' : '$done of ${tasks.length} steps completed'} · ${seconds ~/ 60}m ${seconds % 60}s elapsed',
            ),
            if (controller.busy)
              const Text(
                'The current operation has no reliable time estimate.',
              ),
            if (failed)
              const Text(
                'Completed steps remain applied. Review the error before retrying.',
              ),
          ],
        ),
      ),
    );
  }
}
