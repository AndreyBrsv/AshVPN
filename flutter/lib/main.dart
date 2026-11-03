import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path/path.dart' as path;

import 'appearance.dart';
import 'appearance_dialog.dart';
import 'connection_details.dart';
import 'app_update.dart';
import 'app_update_dialog.dart';
import 'json_file_store.dart';
import 'create_client_dialog.dart';
import 'import_client_dialog.dart';
import 'credential_vault.dart';
import 'credentials_card.dart';
import 'remote_backend.dart';
import 'server_profiles.dart';
import 'server_template.dart';
import 'setup_secrets.dart';
import 'setup_wizard.dart';
import 'ssh_connection.dart';
import 'template_repository.dart';
import 'ui_components.dart';
import 'workspace_controller.dart';
import 'workspace_shell.dart';
import 'server_workspace.dart';
import 'vless_connection.dart';

export 'workspace_controller.dart' show SshConnector;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final appearance = AppearanceController(
    repository: JsonAppearanceRepository(
      JsonFileStore(
        File(path.join(appDataDirectory().path, 'appearance-settings.json')),
      ),
    ),
  );
  await appearance.initialize();
  runApp(AshappApp(appearance: appearance));
}

class AshappApp extends StatefulWidget {
  const AshappApp({super.key, this.home = const HomePage(), this.appearance});
  final Widget home;
  final AppearanceController? appearance;

  @override
  State<AshappApp> createState() => _AshappAppState();
}

class _AshappAppState extends State<AshappApp> {
  // A memory-only default keeps embedded views and tests free of local I/O.
  final _fallback = AppearanceController();
  AppearanceController get appearance => widget.appearance ?? _fallback;

  @override
  void dispose() {
    _fallback.dispose();
    super.dispose();
  }

  ThemeData theme(Brightness brightness) {
    final colors = ColorScheme.fromSeed(
      seedColor: const Color(0xff5856d6),
      brightness: brightness,
    );
    return ThemeData(
      useMaterial3: true,
      colorScheme: colors,
      fontFamily: Platform.isWindows ? 'Segoe UI' : null,
      scaffoldBackgroundColor: brightness == Brightness.light
          ? const Color(0xfff2f2f7)
          : const Color(0xff141416),
      appBarTheme: AppBarTheme(
        backgroundColor: colors.surface,
        centerTitle: false,
        scrolledUnderElevation: 0,
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        color: colors.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: colors.surfaceContainerLowest,
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(minimumSize: const Size(88, 48)),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(minimumSize: const Size(88, 48)),
      ),
      textTheme: const TextTheme(
        bodyLarge: TextStyle(fontSize: 17),
        bodyMedium: TextStyle(fontSize: 16, height: 1.4),
      ),
    );
  }

  @override
  Widget build(BuildContext context) => AppearanceScope(
    controller: appearance,
    child: ListenableBuilder(
      listenable: appearance,
      builder: (context, _) => MaterialApp(
        title: 'Ashapp',
        debugShowCheckedModeBanner: false,
        theme: theme(Brightness.light),
        darkTheme: theme(Brightness.dark),
        themeMode: appearance.mode,
        home: widget.home,
      ),
    ),
  );
}

class HomePage extends StatefulWidget {
  const HomePage({
    super.key,
    this.controller,
    this.connector = SshConnection.connect,
    this.backendFactory = RemoteBackend.new,
    this.profiles,
    this.templates,
    this.vault,
    this.updates,
  });
  final WorkspaceController? controller;
  final SshConnector connector;
  final RemoteBackend Function(SshConnection, String) backendFactory;
  final ServerProfiles? profiles;
  final TemplateRepository? templates;
  final CredentialVault? vault;
  final AppUpdateController? updates;
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  late final ServerWorkspace workspace;
  late final AppUpdateController updates;
  WorkspaceController get vm => workspace.current;
  int page = 0;
  bool opening = false;
  bool get busy => vm.busy || opening || updates.locksWorkspace;
  @override
  void initState() {
    super.initState();
    final initial =
        widget.controller ??
        WorkspaceController(
          profilesRepository:
              widget.profiles ??
              ServerProfiles(
                File(path.join(appDataDirectory().path, 'servers.json')),
              ),
          templatesRepository:
              widget.templates ??
              TemplateRepository(
                File(path.join(appDataDirectory().path, 'templates.json')),
              ),
          vault: widget.vault ?? CredentialVault(PlatformSecretStore()),
          connector: widget.connector,
          backendFactory: widget.backendFactory,
        );
    workspace = ServerWorkspace(initial);
    initial.initialize();
    updates =
        widget.updates ??
        AppUpdateController(
          repository: UpdateRepository(
            transport: GitHubUpdateTransport(),
            cache: Directory(path.join(appDataDirectory().path, 'updates')),
          ),
          runtime: NativeUpdateRuntime(),
          preferences: JsonFileStore(
            File(path.join(appDataDirectory().path, 'update-settings.json')),
          ),
        );
    // Injected workspace tests do not make live update requests.
    updates.addListener(updateOperationGate);
    if (widget.updates != null || widget.controller == null) updates.start();
  }

  @override
  void dispose() {
    updates.removeListener(updateOperationGate);
    if (widget.updates == null) updates.dispose();
    workspace.dispose();
    workspace.closeSessions(preserve: widget.controller);
    super.dispose();
  }

  bool get canInstallUpdate =>
      !opening && workspace.sessions.every((session) => !session.busy);

  void updateOperationGate() {
    workspace.operationsSuspended = updates.locksWorkspace;
  }

  Future<void> showUpdates() => showDialog<void>(
    context: context,
    builder: (_) => AppUpdateDialog(
      controller: updates,
      workspace: workspace,
      canInstall: () => canInstallUpdate,
    ),
  );

  Future<void> checkForUpdates() async {
    final dialog = showUpdates();
    await updates.check();
    await dialog;
  }

  Future<void> connect([ServerProfile? profile]) async {
    if (opening) return;
    final existing = profile == null ? null : workspace.find(profile);
    if (existing != null) {
      workspace.select(existing);
      if (existing.connected || existing.busy) {
        setState(() => page = 2);
        return;
      }
    }
    final target =
        existing ?? (vm.ssh == null && !vm.busy ? vm : workspace.create());
    setState(() => opening = true);
    await target.initialize();
    if (!mounted) return;
    ConnectionDetails? saved;
    if (profile != null) {
      try {
        saved = await target.savedLogin(profile);
      } catch (_) {
        if (mounted) {
          showNotice(
            context,
            'Saved credentials could not be unlocked. Enter them again.',
          );
        }
      }
    }
    if (!mounted) return;
    final connected = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (_) =>
          ConnectDialog(controller: target, profile: profile, saved: saved),
    );
    if (!mounted) return;
    setState(() {
      opening = false;
      if (connected == true) {
        workspace.select(target);
        page = 2;
      }
    });
  }

  Future<void> wizard({
    bool edit = false,
    bool current = false,
    ServerTemplate? template,
  }) async {
    if (opening || (current && vm.busy)) return;
    final target = edit || current || (vm.ssh == null && !vm.busy)
        ? vm
        : workspace.create();
    setState(() => opening = true);
    try {
      await target.initialize();
      final secrets = template == null
          ? const SetupSecrets()
          : await target.templateSecrets(template.name);
      if (!mounted) return;
      final result = await Navigator.push<bool>(
        context,
        MaterialPageRoute(
          builder: (_) => SetupWizard(
            controller: target,
            editTemplate: edit,
            useConnected: current,
            initial: template,
            secrets: secrets,
          ),
        ),
      );
      if (mounted) {
        if (target.connected || result == true) workspace.select(target);
        await vm.initialize();
        if (mounted && result == true) setState(() => page = edit ? 1 : 2);
      }
    } catch (_) {
      if (mounted) {
        showNotice(
          context,
          'Could not unlock the template. Check the OS credential store.',
        );
      }
    } finally {
      if (mounted) setState(() => opening = false);
    }
  }

  Future<List<String>?> values(
    String title,
    List<InputSpec> fields, {
    String action = 'Continue',
    String? description,
  }) => showDialog<List<String>>(
    context: context,
    builder: (_) => ValuesDialog(
      title: title,
      fields: fields,
      action: action,
      description: description,
    ),
  );
  Future<void> addClient() async {
    final target = vm;
    final sources = target.clientSources;
    if (sources.isEmpty) return;
    final result = await showDialog<ClientDraft>(
      context: context,
      builder: (_) => CreateClientDialog(
        sources: sources,
        endpoint: '${target.ssh!.host}:${target.ssh!.port}',
      ),
    );
    if (result != null) {
      await target.addClient(
        result.name,
        source: result.source,
        dns: result.dns,
      );
    }
  }

  Future<void> importClient(Map<String, dynamic> client) async {
    final target = vm;
    final source = client['source'] as String;
    final key = client['public_key'] as String;
    final name = client['name'].toString();
    final endpoint = '${target.ssh!.host}:${target.ssh!.port} · $source';
    final imported = await showDialog<ImportedClientConfiguration>(
      context: context,
      builder: (_) => ImportClientDialog(endpoint: endpoint, name: name),
    );
    if (imported != null) {
      await target.importClientConfiguration(
        name,
        imported.content,
        source: source,
        publicKey: key,
        replace: imported.replace,
      );
    }
  }

  Future<void> addAdmin() async {
    final target = vm;
    final result = await values(
      'Create administrator',
      [
        const InputSpec('Administrator username'),
        const InputSpec('Administrator password', secret: true),
      ],
      action: 'Create and verify',
      description: 'Creates or updates the account and grants passwordless sudo. Its password will be replaced if it exists. Ashapp will verify SSH access and use this account.',
    );
    if (result != null) {
      await target.createAdministrator(result[0].trim(), result[1]);
    }
  }

  Future<void> rootPassword() async {
    final target = vm;
    final result = await values('Change root password', [
      const InputSpec('New root password', secret: true),
    ], action: 'Change password');
    if (result != null) await target.changeRootPassword(result.single);
  }

  Future<void> socksSettings() async {
    final target = vm;
    final exists =
        target.server['socks5_configured'] == true ||
        target.server['socks5'] == true;
    if (exists && !await target.readSocks()) return;
    if (!mounted) return;
    final result = await values(
      exists ? 'Replace SOCKS5 credentials' : 'Install SOCKS5',
      [
        InputSpec('SOCKS5 TCP port', initial: '${target.socks?.port ?? 1080}'),
        InputSpec('SOCKS5 username', initial: target.socks?.user ?? ''),
        InputSpec(
          'SOCKS5 password',
          initial: target.socks?.password ?? '',
          secret: true,
        ),
      ],
      action: exists ? 'Replace and verify' : 'Install',
      description: exists
          ? 'Existing SOCKS5 connections will be interrupted. Clients must use the new credentials afterwards.'
          : 'Docker will be installed if needed. Use letters, numbers or underscores; the password needs at least 8 characters.',
    );
    if (result != null) {
      await target.configureSocks(
        int.tryParse(result[0]) ?? 0,
        result[1].trim(),
        result[2],
        replace: exists,
      );
    }
  }

  Future<void> service(String kind, String operation) async {
    final target = vm;
    if (operation != 'start' &&
        !await confirmAction(
          context,
          '${operation == 'stop' ? 'Stop' : 'Restart'} ${kind == 'awg'
              ? 'AmneziaWG'
              : kind == 'vless'
              ? 'VLESS / sing-box'
              : 'SOCKS5'}?',
          'Active connections to this service will be interrupted.',
          action: operation == 'stop' ? 'Stop' : 'Restart',
        )) {
      return;
    }
    await target.service(kind, operation);
  }

  Widget empty(String title, String description) => SectionCard(
    title: title,
    subtitle: description,
    children: [
      FilledButton(
        onPressed: opening ? null : () => connect(),
        child: const Text('Connect to a server'),
      ),
    ],
  );
  Widget serversPage() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      SectionCard(
        title: 'Your servers',
        subtitle: 'Prepare a VPS from a template or manage an existing server.',
        children: [
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              FilledButton.icon(
                onPressed: opening ? null : () => wizard(),
                icon: const Icon(Icons.add),
                label: const Text('Set up a server'),
              ),
              OutlinedButton(
                onPressed: opening ? null : () => connect(),
                child: const Text('Connect to existing'),
              ),
            ],
          ),
        ],
      ),
      if (vm.profiles.isEmpty)
        const Padding(
          padding: EdgeInsets.all(24),
          child: Text(
            'Your saved servers will appear here. Server profiles store only IP addresses and SSH ports.',
          ),
        ),
      for (final profile in vm.profiles)
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Wrap(
              alignment: WrapAlignment.spaceBetween,
              crossAxisAlignment: WrapCrossAlignment.center,
              spacing: 16,
              runSpacing: 12,
              children: [
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.dns_outlined),
                    const SizedBox(width: 16),
                    Flexible(
                      child: Text(
                        '${profile.ip}:${profile.sshPort}',
                        overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ),
                  ],
                ),
                Wrap(
                  spacing: 8,
                  children: [
                    OutlinedButton(
                      onPressed: opening ? null : () => connect(profile),
                      child: const Text('Connect'),
                    ),
                    IconButton(
                      tooltip: 'Forget server on this device',
                      icon: const Icon(Icons.delete_outline),
                      onPressed: busy
                          ? null
                          : () async {
                              final target = vm;

                              if (await confirmAction(
                                context,
                                'Forget server?',
                                'Remove the saved address and SSH credentials from this device? The server and VPN clients will stay intact.',
                                action: 'Forget',
                              )) {
                                await target.removeProfile(profile);
                              }
                            },
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
    ],
  );
  Widget templatesPage() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      SectionCard(
        title: 'Setup templates',
        subtitle: 'Answer once, reuse on another VPS. Every answer can be reviewed and changed before setup.',
        children: [
          FilledButton.icon(
            onPressed: busy ? null : () => wizard(edit: true),
            icon: const Icon(Icons.add),
            label: const Text('Create template'),
          ),
          if (vm.templateCleanupPending)
            const Text(
              'Unlock your OS credential store to remove unused saved answers.',
            ),
          if (vm.templateCleanupPending)
            OutlinedButton(
              onPressed: busy ? null : vm.retryTemplateCleanup,
              child: const Text('Retry protected cleanup'),
            ),
        ],
      ),
      if (vm.templates.isEmpty)
        const Padding(
          padding: EdgeInsets.all(24),
          child: Text(
            'No templates yet. Include account settings, security choices, SOCKS5 and first clients. Passwords are stored separately in the OS credential vault.',
          ),
        ),
      for (final template in vm.templates)
        SectionCard(
          title: template.name,
          subtitle:
              '${template.installAwg ? 'AmneziaWG · UDP ${template.awgPort}' : ''}${template.installVless ? ' · VLESS · TCP ${template.vlessPort}' : ''}${!template.installAwg && !template.installVless ? 'VPN deferred' : ''}${template.installSocks ? ' · SOCKS5' : ''} · ${template.clientNames.length + template.vlessClientNames.length} clients',
          children: [
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton(
                  onPressed: opening ? null : () => wizard(template: template),
                  child: const Text('Use template'),
                ),
                OutlinedButton(
                  onPressed: busy
                      ? null
                      : () => wizard(edit: true, template: template),
                  child: const Text('Edit answers'),
                ),
                TextButton(
                  onPressed: busy
                      ? null
                      : () async {
                          final target = vm;

                          if (await confirmAction(
                            context,
                            'Delete template?',
                            'Delete ${template.name} and its protected answers from this device?',
                            action: 'Delete',
                          )) {
                            await target.removeTemplate(template.name);
                          }
                        },
                  child: const Text('Delete'),
                ),
              ],
            ),
          ],
        ),
    ],
  );
  Widget managementPage() {
    if (!vm.connected) {
      return empty(
        'Manage a server',
        'Connect using an SSH account with root access or passwordless sudo.',
      );
    }
    final awg = vm.server['awg'] == true, socks = vm.server['socks5'] == true;
    final ssh = vm.server['ssh'] as Map? ?? {};
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SectionCard(
          title: 'Server overview',
          subtitle: 'SSH ${vm.ssh!.user} · port ${vm.ssh!.port}',
          children: [
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton(
                  onPressed: busy ? null : () => vm.refresh(),
                  child: const Text('Refresh status'),
                ),
                OutlinedButton(
                  onPressed: busy ? null : () => wizard(current: true),
                  child: const Text('Run setup wizard'),
                ),
              ],
            ),
            if (vm.server['userspace'] == true)
              const Padding(
                padding: EdgeInsets.only(top: 16),
                child: Text(
                  'A userspace AmneziaWG process was detected. Ashapp requires the kernel module. Existing services will not be replaced.',
                ),
              ),
            if (vm.server['awg_error'] != null)
              Padding(
                padding: const EdgeInsets.only(top: 16),
                child: Text(vm.server['awg_error'].toString()),
              ),
            if (vm.server['vpn_detection_error'] != null)
              Padding(
                padding: const EdgeInsets.only(top: 16),
                child: Text(vm.server['vpn_detection_error'].toString()),
              ),
            if (vm.server['reboot_required'] == true)
              const Padding(
                padding: EdgeInsets.only(top: 16),
                child: Text(
                  'The operating system reports that a reboot is required.',
                ),
              ),
          ],
        ),
        SectionCard(
          title: 'AmneziaWG',
          subtitle:
              '${awg ? 'Running' : 'Stopped or not installed'}${vm.server['kernel'] == true ? ' · kernel interface verified' : ''}${vm.server['awg_port'] != null ? ' · UDP ${vm.server['awg_port']}' : ''}',
          children: [
            if (vm.server['interface'] != null)
              serviceButtons('awg', awg)
            else if (vm.server['awg_configured'] != true)
              OutlinedButton(
                onPressed: busy ? null : () => wizard(current: true),
                child: const Text('Configure VPN'),
              ),
            const SizedBox(height: 12),
            const Text(
              'Import exported client configurations into AmneziaWG or another compatible app. Ashapp manages the server; it does not run a local VPN tunnel.',
            ),
          ],
        ),
        for (final source in vm.server['external_awg'] as List? ?? [])
          SectionCard(
            title: 'AmneziaVPN · ${source['source']}',
            subtitle: source['running'] == true
                ? 'Running in Docker'
                : 'Container stopped',
            children: const [
              Text(
                'Manage clients in Clients. Use AmneziaVPN for container service controls. Ashapp will not replace this deployment.',
              ),
            ],
          ),
        SectionCard(
          title: 'VLESS + Reality + XTLS Vision',
          subtitle:
              '${vm.server['vless'] == true ? 'Running' : 'Stopped or not installed'}${vm.server['vless_port'] != null ? ' · TCP ${vm.server['vless_port']} · ${vm.server['vless_sni']}' : ''}',
          children: [
            if (vm.server['vless_error'] != null)
              Text(vm.server['vless_error'].toString()),
            if (vm.server['vless_configured'] == true &&
                vm.server['vless_error'] == null)
              serviceButtons('vless', vm.server['vless'] == true)
            else if (vm.server['vless_configured'] != true)
              OutlinedButton(
                onPressed: busy ? null : () => wizard(current: true),
                child: const Text('Configure VLESS'),
              ),
            const SizedBox(height: 12),
            const Text(
              'A separate sing-box service, compatible with running AmneziaWG. Manage each device in Clients and export its VLESS link or client JSON. Client changes briefly restart VLESS connections; AmneziaWG is unaffected.',
            ),
          ],
        ),
        SectionCard(
          title: 'SOCKS5',
          subtitle:
              '${socks ? 'Running' : 'Stopped or not installed'}${vm.server['socks5_port'] != null ? ' · TCP ${vm.server['socks5_port']}' : ''}',
          children: [
            if (vm.server['socks5_configured'] == true || socks) ...[
              serviceButtons('socks', socks),
              const SizedBox(height: 12),
            ],
            OutlinedButton(
              onPressed: busy ? null : socksSettings,
              child: Text(
                vm.server['socks5_configured'] == true || socks
                    ? 'Manage SOCKS5 credentials'
                    : 'Install SOCKS5',
              ),
            ),
            if (vm.server['socks5_configured'] == true || socks)
              TextButton(
                onPressed: busy
                    ? null
                    : () async {
                        final target = vm;

                        if (await target.readSocks() && mounted) {
                          setState(() => page = 4);
                        }
                      },
                child: const Text('Show connection details'),
              ),
          ],
        ),
        SectionCard(
          title: 'Server access and security',
          children: [
            Text(
              'Root SSH: ${ssh['permitrootlogin'] ?? 'Unknown'} · Password login: ${ssh['passwordauthentication'] ?? 'Unknown'}',
            ),
            const SizedBox(height: 8),
            Text(
              'Ping replies: ${vm.server['icmp_blocked'] == true ? 'Blocked' : 'Not blocked by Ashapp'}',
            ),
            const SizedBox(height: 16),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton(
                  onPressed: busy ? null : addAdmin,
                  child: const Text('Create administrator'),
                ),
                OutlinedButton(
                  onPressed: busy ? null : rootPassword,
                  child: const Text('Change root password'),
                ),
                if (vm.ssh!.user != 'root' && ssh['permitrootlogin'] != 'no')
                  OutlinedButton(
                    onPressed: busy
                        ? null
                        : () async {
                            final target = vm;

                            if (await confirmAction(
                              context,
                              'Disable root SSH login?',
                              'Ashapp will independently verify this administrator login and sudo before changing SSH.',
                            )) {
                              await target.disableRoot();
                            }
                          },
                    child: const Text('Disable root SSH login'),
                  ),
                OutlinedButton(
                  onPressed: busy
                      ? null
                      : () async {
                          final target = vm;

                          final blocked = target.server['icmp_blocked'] == true;
                          if (await confirmAction(
                            context,
                            blocked
                                ? 'Allow ping replies?'
                                : 'Block ping replies?',
                            blocked
                                ? 'Remove the Ashapp IPv4 echo-request block. Other firewall rules remain in effect.'
                                : 'Block IPv4 echo requests without blocking SSH or VPN.',
                          )) {
                            await target.blockPing(!blocked);
                          }
                        },
                  child: Text(
                    vm.server['icmp_blocked'] == true
                        ? 'Allow ping'
                        : 'Block ping',
                  ),
                ),
              ],
            ),
            if (vm.users.isNotEmpty) ...[
              const SizedBox(height: 20),
              const Text('Regular Linux accounts'),
              for (final user in vm.users)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.person_outline),
                  title: Text(user['name'].toString()),
                  trailing: IconButton(
                    tooltip: 'Saved credentials',
                    onPressed: busy
                        ? null
                        : () async {
                            final target = vm;

                            if (await target.readSavedAccount(
                                  user['name'].toString(),
                                ) &&
                                mounted) {
                              setState(() => page = 4);
                            }
                          },
                    icon: const Icon(Icons.key_outlined),
                  ),
                  subtitle: Text('UID ${user['uid']} · ${user['shell']}'),
                ),
            ],
            const SizedBox(height: 16),
            TextButton(
              onPressed: busy
                  ? null
                  : () async {
                      final target = vm;

                      if (await confirmAction(
                        context,
                        'Reboot server?',
                        'VPN, SOCKS5 and SSH connections will be interrupted. Reconnect after the server starts.',
                        action: 'Reboot',
                      )) {
                        await target.reboot();
                      }
                    },
              child: const Text('Reboot server'),
            ),
          ],
        ),
        if (vm.log.isNotEmpty)
          ExpansionTile(
            title: const Text('Activity details'),
            children: [
              Padding(
                padding: const EdgeInsets.all(16),
                child: SelectableText(vm.log),
              ),
            ],
          ),
      ],
    );
  }

  Widget serviceButtons(String kind, bool running) => Wrap(
    spacing: 8,
    runSpacing: 8,
    children: [
      OutlinedButton(
        onPressed: busy
            ? null
            : () => service(kind, running ? 'stop' : 'start'),
        child: Text(running ? 'Stop' : 'Start'),
      ),
      OutlinedButton(
        onPressed: busy ? null : () => service(kind, 'restart'),
        child: const Text('Restart'),
      ),
    ],
  );
  Widget clientsPage() => !vm.connected
      ? empty(
          'VPN clients',
          'Connect to the server to create clients and manage access.',
        )
      : Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            SectionCard(
              title: 'VPN clients',
              subtitle: 'Choose a protocol for each device. AmneziaWG and VLESS can run together on this server. Each client has separate access credentials.',
              children: [
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    FilledButton(
                      onPressed: busy || vm.clientSources.isEmpty
                          ? null
                          : addClient,
                      child: const Text('Create client'),
                    ),
                    OutlinedButton(
                      onPressed: busy ? null : () => vm.refresh(),
                      child: const Text('Refresh'),
                    ),
                  ],
                ),
                if ((vm.server['external_awg'] as List? ?? []).isNotEmpty)
                  const Padding(
                    padding: EdgeInsets.only(top: 16),
                    child: Text(
                      'Choose the VPN installation when creating a client. Names and access changes are saved for AmneziaVPN too. Avoid editing the same VPN in both apps at once.',
                    ),
                  )
                else if (vm.clientSources.isEmpty)
                  const Padding(
                    padding: EdgeInsets.only(top: 16),
                    child: Text(
                      'Saved clients are shown even when a VPN is stopped. Configure VLESS or start a supported AmneziaWG installation in Manage to create clients.',
                    ),
                  ),
              ],
            ),
            if (vm.clientsError.isNotEmpty)
              Padding(
                padding: const EdgeInsets.all(24),
                child: Text(vm.clientsError),
              ),
            for (final warning in vm.clientWarnings)
              Padding(padding: const EdgeInsets.all(12), child: Text(warning)),
            if (vm.clients.isEmpty &&
                vm.clientsError.isEmpty &&
                vm.clientWarnings.isEmpty)
              const Padding(
                padding: EdgeInsets.all(24),
                child: Text(
                  'No VPN clients found in the detected configurations.',
                ),
              ),
            for (final client in vm.clients)
              SectionCard(
                title: client['name'].toString(),
                subtitle:
                    '${vpnSourceLabel(client['source'] as String? ?? 'Host')} · ${client['addresses'] ?? ''}${client['stats_available'] == false
                        ? ' · Live status unavailable'
                        : (client['handshake'] as int? ?? 0) > 0
                        ? ' · Last handshake ${DateTime.fromMillisecondsSinceEpoch((client['handshake'] as int) * 1000).toLocal()}'
                        : ' · No handshake yet'}',
                children: [
                  if (client['configured'] == false)
                    const Padding(
                      padding: EdgeInsets.only(bottom: 12),
                      child: Text(
                        'Saved name only: no current peer configuration was found.',
                      ),
                    ),
                  if (client['can_export'] == false)
                    const Padding(
                      padding: EdgeInsets.only(bottom: 12),
                      child: Text(
                        'The original private configuration is not saved here. Import its .conf to enable key copying and QR later. A private key cannot be recovered from a public key.',
                      ),
                    ),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      IconButton.filledTonal(
                        tooltip: 'Copy connection',
                        onPressed: busy || client['can_export'] == false
                            ? null
                            : () => copyClientConnection(
                                context,
                                vm,
                                client['name'].toString(),
                                source: client['source'] as String?,
                                publicKey: client['public_key'] as String?,
                              ),
                        icon: const Icon(Icons.copy),
                      ),
                      OutlinedButton.icon(
                        onPressed: busy || client['can_export'] == false
                            ? null
                            : () => exportClient(
                                context,
                                vm,
                                client['name'].toString(),
                                source: client['source'] as String?,
                                publicKey: client['public_key'] as String?,
                              ),
                        icon: const Icon(Icons.key),
                        label: const Text('Get configuration'),
                      ),
                      OutlinedButton.icon(
                        onPressed: busy || client['can_export'] == false
                            ? null
                            : () => exportClient(
                                context,
                                vm,
                                client['name'].toString(),
                                source: client['source'] as String?,
                                publicKey: client['public_key'] as String?,
                                showQr: true,
                              ),
                        icon: const Icon(Icons.qr_code_2),
                        label: const Text('Show QR code'),
                      ),
                      if (client['source'] != VlessConnection.source &&
                          client['public_key'] is String)
                        IconButton(
                          tooltip: 'Copy public key',
                          onPressed: () => copyClientValue(
                            context,
                            client['public_key'] as String,
                            'Public key copied. It cannot be used as a full connection configuration.',
                          ),
                          icon: const Icon(Icons.copy_all),
                        ),
                      if (client['can_import'] == true)
                        OutlinedButton(
                          onPressed: busy ? null : () => importClient(client),
                          child: const Text('Import existing .conf'),
                        ),
                      TextButton(
                        onPressed: busy || client['can_rename'] != true
                            ? null
                            : () async {
                                final target = vm;
                                final source = client['source'] as String;
                                final key = client['public_key'] as String;
                                final name = client['name'].toString();
                                final result = await values(
                                  'Rename $name',
                                  [const InputSpec('New client name')],
                                  action: 'Rename',
                                  description:
                                      'Server ${target.ssh!.host}:${target.ssh!.port} · ${vpnSourceLabel(source)}. Access credentials stay the same.${source == VlessConnection.source ? ' VLESS connections may briefly reconnect.' : ''}',
                                );
                                if (result != null) {
                                  await target.renameClient(
                                    name,
                                    result.single.trim(),
                                    source: source,
                                    publicKey: key,
                                  );
                                }
                              },
                        child: const Text('Rename'),
                      ),
                      TextButton(
                        onPressed: busy || client['can_revoke'] == false
                            ? null
                            : () async {
                                final target = vm;

                                final name = client['name'].toString();
                                final source = client['source'] as String?;
                                final publicKey =
                                    client['public_key'] as String?;
                                if (await confirmAction(
                                  context,
                                  'Revoke $name?',
                                  'Server ${target.ssh!.host}:${target.ssh!.port} · ${source ?? 'Host'}. This client will no longer be able to connect.${source == VlessConnection.source ? ' VLESS connections briefly reconnect. AmneziaWG stays running.' : ' Other clients stay connected.'}',
                                  action: 'Revoke',
                                )) {
                                  await target.revokeClient(
                                    name,
                                    source: source,
                                    publicKey: publicKey,
                                  );
                                }
                              },
                        child: const Text('Revoke access'),
                      ),
                    ],
                  ),
                ],
              ),
          ],
        );
  Widget accessPage() => !vm.connected
      ? empty(
          'Connection details',
          'Credentials are shown only for the connected server.',
        )
      : Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Connection details',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            const SizedBox(height: 16),
            CredentialsCard(title: 'SSH access', details: vm.ssh!),
            if (vm.savedAccount != null &&
                vm.savedAccount!.user != vm.ssh!.user)
              CredentialsCard(
                title: vm.savedAccount!.user == 'root'
                    ? 'Root recovery credentials'
                    : 'Saved account credentials',
                details: vm.savedAccount!,
              ),
            if (vm.ssh!.user != 'root') ...[
              OutlinedButton(
                onPressed: busy ? null : () => vm.readSavedAccount('root'),
                child: const Text('Load saved root credentials'),
              ),
              const SizedBox(height: 8),
              const Text(
                'Saved root credentials do not enable root SSH. Use your hosting console for recovery if root SSH is disabled.',
              ),
            ],
            if (vm.socks != null)
              CredentialsCard(title: 'SOCKS5 access', details: vm.socks!),
            if (vm.server['socks5_configured'] == true && vm.socks == null)
              OutlinedButton(
                onPressed: busy ? null : () => vm.readSocks(),
                child: const Text('Load SOCKS5 credentials'),
              ),
            const SizedBox(height: 16),
            const Text(
              'Passwords are masked by default. Copy actions include the password. Saved SSH credentials and protected template answers use OS secure storage.',
            ),
            const SizedBox(height: 16),
            OutlinedButton(
              onPressed: busy
                  ? null
                  : () async {
                      final target = vm;

                      if (await confirmAction(
                        context,
                        'Forget saved SSH credentials?',
                        'Remove the saved login and password from this device. The current session remains open.',
                      )) {
                        await target.forgetPassword();
                      }
                    },
              child: const Text('Forget saved SSH credentials'),
            ),
          ],
        );

  Widget serverSelector() {
    final choices = workspace.sessions.where((target) => target.ssh != null);
    String status(WorkspaceController target) => target.busy
        ? 'Working'
        : target.connected
        ? 'Connected'
        : 'Disconnected';
    final address = vm.ssh == null
        ? 'Select a server'
        : '${vm.ssh!.host}:${vm.ssh!.port}';
    return Material(
      key: ObjectKey(vm),
      color: Theme.of(context).colorScheme.surfaceContainerLow,
      borderRadius: BorderRadius.circular(16),
      clipBehavior: Clip.antiAlias,
      child: PopupMenuButton<WorkspaceController>(
        tooltip: 'Switch server',
        enabled: !opening && choices.isNotEmpty,
        initialValue: vm,
        onSelected: (target) async {
          workspace.select(target);
          if (!target.busy) await target.initialize();
        },
        itemBuilder: (_) => [
          for (final target in choices)
            PopupMenuItem(
              value: target,
              child: Text(
                '${target.ssh!.host}:${target.ssh!.port} · ${status(target)}',
              ),
            ),
        ],
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          child: Row(
            children: [
              const Icon(Icons.dns_outlined),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      address,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    Text(
                      vm.ssh == null
                          ? 'Switch between open sessions'
                          : 'SSH · ${status(vm)}',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              const Icon(Icons.expand_more),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: Listenable.merge([workspace, updates]),
    builder: (context, _) {
      final pages = [
        serversPage,
        templatesPage,
        managementPage,
        clientsPage,
        accessPage,
      ];
      return AbsorbPointer(
        absorbing: updates.locksWorkspace,
        child: WorkspaceShell(
          selectedIndex: page,
          onDestinationSelected: (value) => setState(() => page = value),
          serverSelector: workspace.sessions.any((target) => target.ssh != null)
              ? serverSelector()
              : null,
          working: vm.busy,
          error: vm.error,
          message: vm.message,
          actions: [
            if (AppearanceScope.maybeOf(context) case final appearance?)
              IconButton(
                tooltip: 'Appearance',
                icon: const Icon(Icons.brightness_6_outlined),
                onPressed: () => showDialog<void>(
                  context: context,
                  builder: (_) => AppearanceDialog(controller: appearance),
                ),
              ),
            IconButton(
              tooltip: updates.release == null
                  ? 'Check for updates'
                  : 'Update available',
              onPressed: checkForUpdates,
              icon: Badge(
                isLabelVisible: updates.release != null,
                child: const Icon(Icons.system_update_outlined),
              ),
            ),
            if (vm.connected)
              IconButton(
                tooltip: 'Disconnect from this server',
                onPressed: busy ? null : () => vm.disconnect(),
                icon: const Icon(Icons.logout),
              ),
          ],
          child: pages[page](),
        ),
      );
    },
  );
}

class InputSpec {
  const InputSpec(this.label, {this.secret = false, this.initial = ''});
  final String label, initial;
  final bool secret;
}

class ValuesDialog extends StatefulWidget {
  const ValuesDialog({
    super.key,
    required this.title,
    required this.fields,
    required this.action,
    this.description,
  });
  final String title, action;
  final String? description;
  final List<InputSpec> fields;
  @override
  State<ValuesDialog> createState() => _ValuesDialogState();
}

class _ValuesDialogState extends State<ValuesDialog> {
  late final controllers = widget.fields
      .map((f) => TextEditingController(text: f.initial))
      .toList();
  @override
  void dispose() {
    for (final c in controllers) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(widget.title),
    content: SizedBox(
      width: 440,
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (widget.description != null) ...[
              Text(widget.description!),
              const SizedBox(height: 24),
            ],
            for (var i = 0; i < widget.fields.length; i++)
              Padding(
                padding: const EdgeInsets.only(bottom: 16),
                child: widget.fields[i].secret
                    ? SecretField(
                        controller: controllers[i],
                        label: widget.fields[i].label,
                      )
                    : TextFormField(
                        controller: controllers[i],
                        autofocus: i == 0,
                        decoration: InputDecoration(
                          labelText: widget.fields[i].label,
                        ),
                      ),
              ),
          ],
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(
        onPressed: () =>
            Navigator.pop(context, controllers.map((c) => c.text).toList()),
        child: Text(widget.action),
      ),
    ],
  );
}

class ConnectDialog extends StatefulWidget {
  const ConnectDialog({
    super.key,
    required this.controller,
    this.profile,
    this.saved,
  });
  final WorkspaceController controller;
  final ServerProfile? profile;
  final ConnectionDetails? saved;
  @override
  State<ConnectDialog> createState() => _ConnectDialogState();
}

class _ConnectDialogState extends State<ConnectDialog> {
  late final host = TextEditingController(text: widget.profile?.ip ?? '');
  late final port = TextEditingController(
    text: '${widget.profile?.sshPort ?? 22}',
  );
  late final user = TextEditingController(text: widget.saved?.user ?? 'root');
  late final password = TextEditingController(
    text: widget.saved?.password ?? '',
  );
  @override
  void dispose() {
    for (final c in [host, port, user, password]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> connect() async {
    final ok = await widget.controller.connect(
      ConnectionDetails(
        host: host.text.trim(),
        port: int.tryParse(port.text) ?? 0,
        user: user.text.trim(),
        password: password.text,
      ),
      (type, fp) => context.mounted
          ? confirmServerKey(context, type, fp)
          : Future.value(false),
    );
    if (ok && mounted) Navigator.pop(context, true);
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: widget.controller,
    builder: (context, _) {
      final vm = widget.controller;
      return PopScope(
        canPop: !vm.busy,
        child: AlertDialog(
          title: const Text('Connect to a server'),
          content: SizedBox(
            width: 440,
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text(
                    'Use root or an administrator with passwordless sudo.',
                  ),
                  const SizedBox(height: 24),
                  for (final pair in [
                    (host, 'Server IP address'),
                    (port, 'SSH port'),
                    (user, 'Username'),
                  ])
                    Padding(
                      padding: const EdgeInsets.only(bottom: 16),
                      child: TextFormField(
                        controller: pair.$1,
                        enabled: !vm.busy,
                        decoration: InputDecoration(labelText: pair.$2),
                      ),
                    ),
                  SecretField(
                    controller: password,
                    label: 'Password',
                    enabled: !vm.busy,
                  ),
                  CheckboxListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Remember credentials on this device'),
                    subtitle: const Text('Protected by the operating system.'),
                    value: vm.remember,
                    onChanged: vm.busy
                        ? null
                        : (v) => setState(() => vm.remember = v ?? false),
                  ),
                  if (vm.error.isNotEmpty)
                    Semantics(liveRegion: true, child: Text(vm.error)),
                  if (vm.busy) const LinearProgressIndicator(),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: vm.busy ? null : () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: vm.busy ? null : connect,
              child: Text(vm.busy ? 'Connecting…' : 'Connect'),
            ),
          ],
        ),
      );
    },
  );
}
