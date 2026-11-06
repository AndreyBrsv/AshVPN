import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'workspace_controller.dart';

/// Read-only, in-memory output for one captured server session.
class ActivityConsole extends StatefulWidget {
  const ActivityConsole({
    super.key,
    required this.controller,
    this.initiallyExpanded = false,
    this.collapsible = true,
    this.height = 240,
  });

  final WorkspaceController controller;
  final bool initiallyExpanded, collapsible;
  final double height;

  @override
  State<ActivityConsole> createState() => _ActivityConsoleState();
}

class _ActivityConsoleState extends State<ActivityConsole> {
  final _scroll = ScrollController();
  late bool _expanded;
  bool _follow = true;
  String _lastLog = '';

  @override
  void initState() {
    super.initState();
    _expanded = widget.initiallyExpanded;
    widget.controller.addListener(_changed);
    _lastLog = widget.controller.log;
    _scrollToLatest();
  }

  @override
  void didUpdateWidget(ActivityConsole oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != widget.controller) {
      oldWidget.controller.removeListener(_changed);
      widget.controller.addListener(_changed);
      _expanded = widget.initiallyExpanded;
      _follow = true;
      _lastLog = widget.controller.log;
      _scrollToLatest();
    }
  }

  void _changed() {
    final changed = _lastLog != widget.controller.log;
    _lastLog = widget.controller.log;
    setState(() {});
    if (changed && _follow) _scrollToLatest();
  }

  void _scrollToLatest() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && _scroll.hasClients && _follow) {
        _scroll.jumpTo(_scroll.position.maxScrollExtent);
      }
    });
  }

  Future<void> _copy() async {
    final log = widget.controller.log;
    try {
      await Clipboard.setData(ClipboardData(text: log));
      if (mounted) {
        ScaffoldMessenger.maybeOf(
          context,
        )?.showSnackBar(const SnackBar(content: Text('Activity log copied.')));
      }
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.maybeOf(context)?.showSnackBar(
          const SnackBar(content: Text('Could not copy the activity log.')),
        );
      }
    }
  }

  @override
  void dispose() {
    widget.controller.removeListener(_changed);
    _scroll.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final vm = widget.controller;
    final endpoint = vm.ssh == null
        ? 'Current server session'
        : '${vm.ssh!.host}:${vm.ssh!.port}';
    final visible = _expanded || !widget.collapsible;
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (widget.collapsible)
          ListTile(
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.terminal_outlined),
            title: const Text('Server activity'),
            subtitle: Text(
              vm.busy
                  ? 'Live output · $endpoint'
                  : vm.error.isNotEmpty
                  ? 'Operation failed · $endpoint'
                  : 'Session output · $endpoint',
            ),
            trailing: Icon(visible ? Icons.expand_less : Icons.expand_more),
            onTap: () {
              setState(() => _expanded = !_expanded);
              if (_expanded) _scrollToLatest();
            },
          ),
        if (visible) ...[
          if (!widget.collapsible) ...[
            Text(endpoint, style: theme.textTheme.titleSmall),
            const SizedBox(height: 4),
            Semantics(liveRegion: true, child: Text(vm.message)),
            const SizedBox(height: 8),
          ],
          if (vm.error.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.error_outline, color: theme.colorScheme.error),
                  const SizedBox(width: 8),
                  Expanded(child: SelectableText(vm.error)),
                ],
              ),
            ),
          Wrap(
            alignment: WrapAlignment.end,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: 8,
            children: [
              FilterChip(
                label: const Text('Follow output'),
                selected: _follow,
                onSelected: (value) {
                  setState(() => _follow = value);
                  if (value) _scrollToLatest();
                },
              ),
              IconButton(
                tooltip: 'Copy activity log',
                onPressed: vm.log.isEmpty ? null : _copy,
                icon: const Icon(Icons.copy_outlined),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Container(
            height: widget.height,
            decoration: BoxDecoration(
              color: theme.colorScheme.surfaceContainerLow,
              borderRadius: BorderRadius.circular(12),
            ),
            clipBehavior: Clip.antiAlias,
            child: Scrollbar(
              controller: _scroll,
              thumbVisibility: true,
              child: SingleChildScrollView(
                key: const ValueKey('activity-output'),
                controller: _scroll,
                padding: const EdgeInsets.all(16),
                child: SelectableText(
                  vm.log.isEmpty
                      ? vm.busy
                            ? 'Waiting for server output…'
                            : 'No activity in this session yet.'
                      : vm.log,
                  style: theme.textTheme.bodySmall?.copyWith(
                    fontFamily: 'monospace',
                    fontFamilyFallback: const ['Consolas', 'Menlo'],
                    height: 1.5,
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Read-only output. Kept in memory for this session.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ],
    );
  }
}

/// Keeps an open console bound to its original server when selection changes.
Future<void> showActivityConsole(
  BuildContext context,
  WorkspaceController controller,
) => showDialog<void>(
  context: context,
  builder: (context) => AlertDialog(
    scrollable: true,
    title: const Text('Server activity'),
    content: SizedBox(
      width: 760,
      child: SingleChildScrollView(
        child: ActivityConsole(
          controller: controller,
          collapsible: false,
          height: (MediaQuery.sizeOf(context).height * .45).clamp(120, 420),
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('Close'),
      ),
    ],
  ),
);
