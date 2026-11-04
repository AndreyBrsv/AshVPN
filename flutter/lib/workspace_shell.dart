import 'package:flutter/material.dart';

/// Window-sized navigation and chrome, independent of SSH and persistence.
class WorkspaceShell extends StatelessWidget {
  const WorkspaceShell({
    super.key,
    required this.selectedIndex,
    required this.onDestinationSelected,
    required this.actions,
    required this.child,
    this.serverSelector,
    this.working = false,
    this.error = '',
    this.message = '',
  });

  final int selectedIndex;
  final ValueChanged<int> onDestinationSelected;
  final List<Widget> actions;
  final Widget child;
  final Widget? serverSelector;
  final bool working;
  final String error;
  final String message;

  static const destinations = [
    (Icons.dns_outlined, 'Servers'),
    (Icons.auto_awesome_mosaic_outlined, 'Templates'),
    (Icons.tune, 'Manage'),
    (Icons.devices, 'Clients'),
    (Icons.key_outlined, 'Access'),
  ];

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final compact = constraints.maxWidth < 900;
      final scale = MediaQuery.textScalerOf(context).scale(14) / 14;
      final colors = Theme.of(context).colorScheme;
      return Scaffold(
        appBar: AppBar(
          automaticallyImplyLeading: false,
          toolbarHeight: 48,
          actions: [...actions, const SizedBox(width: 8)],
        ),
        bottomNavigationBar: compact
            ? NavigationBar(
                height: scale > 1.3 ? 88 : 72,
                selectedIndex: selectedIndex,
                labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
                onDestinationSelected: onDestinationSelected,
                destinations: [
                  for (final (icon, label) in destinations)
                    NavigationDestination(icon: Icon(icon), label: label),
                ],
              )
            : null,
        body: SafeArea(
          child: Row(
            children: [
              if (!compact)
                NavigationRail(
                  extended: constraints.maxWidth >= 1100 * scale,
                  labelType: constraints.maxWidth >= 1100 * scale
                      ? NavigationRailLabelType.none
                      : NavigationRailLabelType.all,
                  selectedIndex: selectedIndex,
                  onDestinationSelected: onDestinationSelected,
                  destinations: [
                    for (final (icon, label) in destinations)
                      NavigationRailDestination(
                        icon: Icon(icon),
                        label: Text(label),
                      ),
                  ],
                ),
              Expanded(
                child: Column(
                  children: [
                    if (serverSelector != null)
                      Padding(
                        padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
                        child: serverSelector!,
                      ),
                    if (working) const LinearProgressIndicator(),
                    Expanded(
                      child: SingleChildScrollView(
                        // Keep each page/server's scroll position independent.
                        key: PageStorageKey((
                          selectedIndex,
                          serverSelector?.key,
                        )),
                        padding: EdgeInsets.fromLTRB(
                          compact ? 16 : 24,
                          16,
                          compact ? 16 : 24,
                          8,
                        ),
                        child: Align(
                          alignment: Alignment.topCenter,
                          child: ConstrainedBox(
                            constraints: const BoxConstraints(maxWidth: 840),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                if (error.isNotEmpty)
                                  Padding(
                                    padding: const EdgeInsets.only(bottom: 12),
                                    child: Material(
                                      color: colors.errorContainer,
                                      borderRadius: BorderRadius.circular(12),
                                      child: Padding(
                                        padding: const EdgeInsets.all(16),
                                        child: Semantics(
                                          liveRegion: true,
                                          child: Text(error),
                                        ),
                                      ),
                                    ),
                                  ),
                                child,
                              ],
                            ),
                          ),
                        ),
                      ),
                    ),
                    if (message.isNotEmpty)
                      Padding(
                        padding: const EdgeInsets.fromLTRB(20, 4, 20, 8),
                        child: Align(
                          alignment: Alignment.centerLeft,
                          child: Semantics(
                            liveRegion: true,
                            child: Text(
                              message,
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: Theme.of(context).textTheme.bodySmall
                                  ?.copyWith(color: colors.onSurfaceVariant),
                            ),
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ],
          ),
        ),
      );
    },
  );
}
