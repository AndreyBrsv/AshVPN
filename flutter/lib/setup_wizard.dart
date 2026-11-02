import 'package:flutter/material.dart';

import 'connection_details.dart';
import 'credentials_card.dart';
import 'server_template.dart';
import 'setup_secrets.dart';
import 'ui_components.dart';
import 'workspace_controller.dart';
import 'vless_connection.dart';

/// Manual setup and templates edit the same questions and execute one plan.
class SetupWizard extends StatefulWidget {
  const SetupWizard({
    super.key,
    required this.controller,
    this.editTemplate = false,
    this.useConnected = false,
    this.initial,
    this.secrets = const SetupSecrets(),
  });
  final WorkspaceController controller;
  final bool editTemplate, useConnected;
  final ServerTemplate? initial;
  final SetupSecrets secrets;
  @override
  State<SetupWizard> createState() => _SetupWizardState();
}

class _SetupWizardState extends State<SetupWizard> {
  final host = TextEditingController(),
      port = TextEditingController(text: '22');
  final login = TextEditingController(text: 'root'),
      loginPassword = TextEditingController();
  final name = TextEditingController(), rootPassword = TextEditingController();
  final adminName = TextEditingController(),
      adminPassword = TextEditingController();
  final keyText = TextEditingController(),
      awgPort = TextEditingController(text: '585');
  final dns = TextEditingController(text: '1.1.1.1'),
      socksPort = TextEditingController(text: '1080');
  final socksUser = TextEditingController(),
      socksPassword = TextEditingController();
  final clientNames = TextEditingController();
  final vlessPort = TextEditingController(text: '443'),
      realitySni = TextEditingController(text: 'www.microsoft.com'),
      vlessClientNames = TextEditingController();
  bool installVless = false;
  String realityFingerprint = 'chrome';
  int step = 0;
  bool blockPing = false,
      disableRoot = false,
      installAwg = true,
      installSocks = false;
  bool upgrade = false,
      changeRoot = false,
      createAdmin = true,
      savingTemplate = false,
      loading = false;
  String? selection;
  String localError = '';
  WorkspaceController get vm => widget.controller;
  bool get busy => vm.busy || loading;
  static const labels = [
    'Server',
    'Account',
    'Security',
    'Services',
    'Clients',
    'Review',
    'Result',
  ];

  @override
  void initState() {
    super.initState();
    if (widget.initial != null) {
      _apply(widget.initial!, widget.secrets);
      if (vm.templates.any((t) => t.name == widget.initial!.name)) {
        selection = 'template:${widget.initial!.name}';
      }
    }
    if (widget.useConnected && vm.ssh != null) {
      host.text = vm.ssh!.host;
      port.text = '${vm.ssh!.port}';
      login.text = vm.ssh!.user;
      loginPassword.text = vm.ssh!.password;
      createAdmin = widget.initial?.createAdmin ?? false;
    }
  }

  void _apply(ServerTemplate item, SetupSecrets secrets) {
    name.text = item.name;
    blockPing = item.blockPing;
    disableRoot = item.disableRoot;
    installAwg = item.installAwg;
    installSocks = item.installSocks;
    installVless = item.installVless;
    vlessPort.text = '${item.vlessPort}';
    realitySni.text = item.realitySni;
    realityFingerprint = item.realityFingerprint;
    vlessClientNames.text = item.vlessClientNames.join('\n');
    awgPort.text = '${item.awgPort}';
    dns.text = item.awgDns;
    socksPort.text = '${item.socksPort}';
    port.text = '${item.sshPort}';
    clientNames.text = item.clientNames.join('\n');
    upgrade = item.upgradePackages;
    changeRoot = item.changeRootPassword;
    createAdmin = item.createAdmin;
    login.text = secrets.connectionUser;
    loginPassword.text = secrets.connectionPassword;
    rootPassword.text = secrets.rootPassword;
    adminName.text = secrets.adminName;
    adminPassword.text = secrets.adminPassword;
    socksUser.text = secrets.socksUser;
    socksPassword.text = secrets.socksPassword;
    keyText.text = secrets.sshPublicKey;
    if (widget.useConnected && vm.ssh != null) {
      host.text = vm.ssh!.host;
      port.text = '${vm.ssh!.port}';
      login.text = vm.ssh!.user;
      loginPassword.text = vm.ssh!.password;
    }
  }

  Future<void> selectTemplate(String? value) async {
    if (value == null || busy) return;
    if (value == 'manual') {
      setState(() {
        selection = null;
        _apply(
          ServerTemplate(
            name: 'Untitled',
            blockPing: false,
            disableRoot: false,
            installAwg: true,
            installSocks: false,
            awgPort: 585,
            clientNames: [],
          ),
          const SetupSecrets(),
        );
        name.clear();
      });
      return;
    }
    setState(() {
      loading = true;
      localError = '';
    });
    try {
      final templateName = value.substring('template:'.length);
      final answers = vm.templates.firstWhere((t) => t.name == templateName);
      final secrets = await vm.templateSecrets(templateName);
      if (mounted) {
        setState(() {
          _apply(answers, secrets);
          selection = value;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(
          () => localError = 'Could not unlock this template. Check the system credential store.',
        );
      }
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  ServerTemplate answers() => ServerTemplate(
    name: name.text.trim().isEmpty ? 'Session' : name.text.trim(),
    blockPing: blockPing,
    disableRoot: disableRoot,
    installAwg: installAwg,
    installSocks: installSocks,
    installVless: installVless,
    vlessPort: int.tryParse(vlessPort.text) ?? 0,
    realitySni: realitySni.text.trim(),
    realityFingerprint: realityFingerprint,
    vlessClientNames: installVless
        ? vlessClientNames.text
              .split('\n')
              .map((s) => s.trim())
              .where((s) => s.isNotEmpty)
              .toList()
        : [],
    awgPort: int.tryParse(awgPort.text) ?? 0,
    socksPort: int.tryParse(socksPort.text) ?? 0,
    sshPort: int.tryParse(port.text) ?? 0,
    awgDns: dns.text.trim(),
    upgradePackages: upgrade,
    changeRootPassword: changeRoot,
    createAdmin: createAdmin,
    clientNames: installAwg
        ? clientNames.text
              .split(RegExp(r'[,\s]+'))
              .where((s) => s.isNotEmpty)
              .toList()
        : [],
  );
  SetupSecrets secrets() => SetupSecrets(
    connectionUser: login.text.trim(),
    connectionPassword: loginPassword.text,
    rootPassword: rootPassword.text,
    adminName: adminName.text.trim(),
    adminPassword: adminPassword.text,
    socksUser: socksUser.text.trim(),
    socksPassword: socksPassword.text,
    sshPublicKey: keyText.text.trim(),
  );
  String? validateStep() {
    if (step == 0) {
      if (widget.editTemplate) {
        if (name.text.trim().isEmpty || name.text.trim().length > 80) {
          return 'Enter a template name with up to 80 characters.';
        }
      } else if (host.text.trim().isEmpty ||
          login.text.trim().isEmpty ||
          loginPassword.text.isEmpty ||
          (int.tryParse(port.text) ?? 0) < 1 ||
          (int.tryParse(port.text) ?? 65536) > 65535) {
        return 'Enter the address, port, username and password.';
      }
    }
    if (step == 1) {
      if (changeRoot && !SetupSecrets.passwordValid(rootPassword.text)) {
        return 'The new root password needs at least 8 characters.';
      }
      if (createAdmin &&
          (!SetupSecrets.usernameValid(adminName.text.trim()) ||
              !SetupSecrets.passwordValid(adminPassword.text))) {
        return 'Enter a valid administrator name and an 8-character password.';
      }
    }
    if (step >= 3) {
      try {
        final item = answers();
        return secrets().validate(
          item,
          activeUser: widget.editTemplate ? null : vm.ssh?.user,
        );
      } on FormatException {
        return 'Check the DNS address, ports and client names (up to 15 letters, numbers, _ or -; no duplicates).';
      }
    }
    return null;
  }

  Future<void> next() async {
    if (busy) return;
    final invalid = validateStep();
    if (invalid != null) {
      setState(() => localError = invalid);
      return;
    }
    setState(() => localError = '');
    if (step == 0 && !widget.editTemplate && !widget.useConnected) {
      final ok = await vm.connect(
        ConnectionDetails(
          host: host.text.trim(),
          port: int.parse(port.text),
          user: login.text.trim(),
          password: loginPassword.text,
        ),
        (type, fingerprint) => context.mounted
            ? confirmServerKey(context, type, fingerprint)
            : Future.value(false),
      );
      if (!ok || !mounted) return;
    }
    if (mounted) setState(() => step++);
  }

  Future<void> run() async {
    if (busy) return;
    final invalid = validateStep();
    if (invalid != null) {
      setState(() => localError = invalid);
      return;
    }
    if ((widget.editTemplate || savingTemplate) && name.text.trim().isEmpty) {
      setState(() => localError = 'Enter a template name.');
      return;
    }
    final item = answers(), protected = secrets();
    if (widget.editTemplate || savingTemplate) {
      if ((!widget.editTemplate || widget.initial?.name != item.name) &&
          vm.templates.any((t) => t.name == item.name)) {
        if (!await confirmAction(
          context,
          'Replace template?',
          'The saved answers for ${item.name} will be replaced.',
        )) {
          return;
        }
      }
      if (!await vm.saveTemplate(item, protected) || !mounted) return;
      if (widget.editTemplate) {
        Navigator.pop(context, true);
        return;
      }
    }
    setState(() {
      step = 6;
      localError = '';
    });
    await vm.provision(item, protected);
  }

  @override
  void dispose() {
    for (final field in [
      host,
      port,
      login,
      loginPassword,
      name,
      rootPassword,
      adminName,
      adminPassword,
      keyText,
      awgPort,
      dns,
      socksPort,
      socksUser,
      socksPassword,
      clientNames,
      vlessPort,
      realitySni,
      vlessClientNames,
    ]) {
      field.dispose();
    }
    super.dispose();
  }

  Widget field(
    TextEditingController controller,
    String label, {
    String? helper,
    int lines = 1,
  }) => Padding(
    padding: const EdgeInsets.only(bottom: 16),
    child: TextFormField(
      controller: controller,
      enabled: !busy,
      maxLines: lines,
      decoration: InputDecoration(labelText: label, helperText: helper),
    ),
  );
  Widget secret(
    TextEditingController controller,
    String label, {
    String? helper,
  }) => Padding(
    padding: const EdgeInsets.only(bottom: 16),
    child: SecretField(
      key: ValueKey('$selection:$label'),
      controller: controller,
      label: label,
      enabled: !busy,
      helper: helper,
    ),
  );
  Widget toggle(
    String title,
    String subtitle,
    bool value,
    ValueChanged<bool> change,
  ) => SwitchListTile.adaptive(
    contentPadding: EdgeInsets.zero,
    title: Text(title),
    subtitle: Text(subtitle),
    value: value,
    onChanged: busy ? null : (v) => setState(() => change(v)),
  );

  Widget content() => switch (step) {
    0 => SectionCard(
      title: widget.editTemplate
          ? 'Reusable answers'
          : 'Where are we setting up?',
      subtitle: widget.editTemplate
          ? 'Store settings and protected answers on this device.'
          : widget.useConnected
          ? 'Using the authenticated server. No reconnect is needed.'
          : 'Use an existing Linux VPS from any hosting provider.',
      children: [
        if (widget.editTemplate) field(name, 'Template name'),
        if (!widget.editTemplate && vm.templates.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(bottom: 24),
            child: DropdownButtonFormField<String>(
              initialValue: selection ?? 'manual',
              decoration: const InputDecoration(labelText: 'Setup method'),
              items: [
                const DropdownMenuItem(
                  value: 'manual',
                  child: Text('Manual · answer each question'),
                ),
                ...vm.templates.map(
                  (t) => DropdownMenuItem(
                    value: 'template:${t.name}',
                    child: Text('Template · ${t.name}'),
                  ),
                ),
              ],
              onChanged: busy ? null : selectTemplate,
            ),
          ),
        if (widget.useConnected)
          Text('${vm.ssh?.host}:${vm.ssh?.port} · ${vm.ssh?.user}')
        else ...[
          if (widget.editTemplate) field(port, 'Default SSH port'),
          if (!widget.editTemplate) ...[
            field(host, 'Server IP address'),
            field(port, 'SSH port'),
          ],
          field(
            login,
            widget.editTemplate ? 'Default SSH username' : 'Username',
          ),
          secret(
            loginPassword,
            widget.editTemplate
                ? 'Default SSH password (optional)'
                : 'Password',
          ),
        ],
        if (!widget.editTemplate)
          CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Remember credentials on this device'),
            subtitle: const Text(
              'Protected by the operating system. JSON profiles contain only IP and port.',
            ),
            value: vm.remember,
            onChanged: busy
                ? null
                : (v) => setState(() => vm.remember = v ?? false),
          ),
      ],
    ),
    1 => SectionCard(
      title: 'Server accounts',
      subtitle: 'Existing account passwords are replaced when selected. Administrator sudo is configured automatically.',
      children: [
        toggle(
          'Change the root password',
          'Optional. The new value will be shown masked in the result.',
          changeRoot,
          (v) => changeRoot = v,
        ),
        if (changeRoot) secret(rootPassword, 'New root password'),
        toggle(
          'Create an administrator',
          'Create or update a regular SSH account with passwordless sudo.',
          createAdmin,
          (v) => createAdmin = v,
        ),
        if (createAdmin) ...[
          field(adminName, 'Administrator username'),
          secret(adminPassword, 'Administrator password'),
        ],
        field(
          keyText,
          'SSH public key (optional)',
          helper: 'Password login stays available. Never paste a private key.',
        ),
      ],
    ),
    2 => SectionCard(
      title: 'Security and updates',
      children: [
        toggle(
          'Disable root SSH login',
          'Only after independently verifying administrator login and sudo.',
          disableRoot,
          (v) => disableRoot = v,
        ),
        toggle(
          'Block ping replies',
          'Block IPv4 echo requests. SSH and VPN remain available.',
          blockPing,
          (v) => blockPing = v,
        ),
        toggle(
          'Update system packages',
          'May require a reboot before VPN installation. Setup will stop and tell you.',
          upgrade,
          (v) => upgrade = v,
        ),
        const SizedBox(height: 16),
        const Text('Unselected options preserve the existing server settings.'),
      ],
    ),
    3 => Column(
      children: [
        SectionCard(
          title: 'VPN',
          children: [
            toggle(
              'Install AmneziaWG',
              'Kernel module only. Existing configurations are preserved.',
              installAwg,
              (v) => installAwg = v,
            ),
            if (installAwg) ...[
              field(awgPort, 'AmneziaWG UDP port'),
              field(dns, 'Client DNS (IPv4)'),
              const Text(
                'IPv4 tunnel · automatic interface detection · generated obfuscation parameters.',
              ),
            ],
            const SizedBox(height: 16),
            toggle(
              'Install VLESS + Reality',
              'XTLS Vision over TCP. Runs alongside AmneziaWG as a separate sing-box service.',
              installVless,
              (v) => installVless = v,
            ),
            if (installVless) ...[
              field(vlessPort, 'VLESS TCP port'),
              field(
                realitySni,
                'Reality SNI / target hostname',
                helper: 'A public TLS 1.3 / HTTP/2 website. Must be reachable from the VPS; its certificate must match this name.',
              ),
              DropdownButtonFormField<String>(
                initialValue: realityFingerprint,
                decoration: const InputDecoration(
                  labelText: 'Client TLS fingerprint',
                ),
                items: [
                  for (final value in VlessConnection.fingerprints)
                    DropdownMenuItem(value: value, child: Text(value)),
                ],
                onChanged: busy
                    ? null
                    : (value) {
                        if (value != null) {
                          setState(() => realityFingerprint = value);
                        }
                      },
              ),
              const SizedBox(height: 16),
              const Text(
                'IPv4 listener · sing-box 1.14.4 · SHA-256 checked download. Existing proxy installations are not adopted. Client edits briefly restart this service only.',
              ),
            ],
            if (!installAwg && !installVless)
              const Text(
                'VPN installation is deferred. You can continue later.',
              ),
          ],
        ),
        SectionCard(
          title: 'SOCKS5 proxy',
          children: [
            toggle(
              'Install SOCKS5',
              'An authenticated proxy in Docker, separate from the kernel VPN.',
              installSocks,
              (v) => installSocks = v,
            ),
            if (installSocks) ...[
              field(socksPort, 'SOCKS5 TCP port'),
              field(socksUser, 'SOCKS5 username'),
              secret(
                socksPassword,
                'SOCKS5 password',
                helper: '8–128 letters, numbers or underscores.',
              ),
            ],
          ],
        ),
      ],
    ),
    4 => SectionCard(
      title: 'First VPN clients',
      subtitle: installAwg || installVless
          ? 'Each device gets its own private configuration. Add more or revoke access later.'
          : 'VPN installation is deferred, so no clients will be created now.',
      children: [
        if (installAwg)
          field(
            clientNames,
            'AmneziaWG client names',
            lines: 5,
            helper: 'One name per line or separated by commas. Up to 15 letters, numbers, _ or -.',
          ),
        if (installVless)
          field(
            vlessClientNames,
            'VLESS client names',
            lines: 5,
            helper: 'One device name per line, up to 64 characters. Each gets a separate UUID and Short ID. Names may match AmneziaWG clients.',
          ),
      ],
    ),
    5 => Column(
      children: [
        SectionCard(
          title: 'Review your answers',
          subtitle: widget.editTemplate
              ? 'These answers will prefill the same setup wizard.'
              : 'Changes start only when you select Run setup.',
          children: [
            if (!widget.editTemplate)
              Text('Server: ${vm.ssh?.host}:${vm.ssh?.port} · ${vm.ssh?.user}'),
            _review('Change root password', changeRoot),
            _review(
              'Create administrator',
              createAdmin,
              detail: adminName.text,
            ),
            _review('Disable root SSH login', disableRoot),
            _review('Block ping replies', blockPing),
            _review('Update system packages', upgrade),
            _review(
              'Install AmneziaWG kernel',
              installAwg,
              detail: 'UDP ${awgPort.text} · DNS ${dns.text}',
            ),
            _review(
              'Install VLESS + Reality + XTLS Vision',
              installVless,
              detail:
                  'TCP ${vlessPort.text} · ${realitySni.text} · $realityFingerprint',
            ),
            _review(
              'Install SOCKS5',
              installSocks,
              detail: 'TCP ${socksPort.text}',
            ),
            _review('Install SSH public key', keyText.text.trim().isNotEmpty),
            const SizedBox(height: 16),
            Text(
              'VPN clients: ${installAwg && clientNames.text.trim().isNotEmpty ? clientNames.text.trim() : 'None'}',
            ),
            Text(
              'VLESS clients: ${installVless && vlessClientNames.text.trim().isNotEmpty ? vlessClientNames.text.trim() : 'None'}',
            ),
            const SizedBox(height: 16),
            const Text(
              'Passwords stay masked and are never written into template JSON. Existing VPN and SOCKS5 settings are preserved.',
            ),
            if (!widget.editTemplate) ...[
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Save these answers as a template'),
                value: savingTemplate,
                onChanged: busy
                    ? null
                    : (v) => setState(() => savingTemplate = v ?? false),
              ),
              if (savingTemplate) field(name, 'Template name'),
            ],
          ],
        ),
        if (widget.editTemplate)
          const Text(
            'Protected answers, including optional default SSH credentials, are saved in the OS credential vault.',
          ),
      ],
    ),
    _ => Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SectionCard(
          title: busy
              ? 'Setting up your server'
              : vm.setupComplete
              ? 'Your server is ready'
              : 'Setup needs attention',
          subtitle: vm.message,
          children: [
            for (final task in vm.tasks)
              ListTile(
                contentPadding: EdgeInsets.zero,
                title: Text(task.label),
                leading: task.state == TaskState.running
                    ? const SizedBox(
                        width: 24,
                        height: 24,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : Icon(switch (task.state) {
                        TaskState.done => Icons.check_circle_outline,
                        TaskState.failed => Icons.error_outline,
                        _ => Icons.radio_button_unchecked,
                      }),
                subtitle: task.state == TaskState.failed
                    ? const Text(
                        'Stopped here. Completed steps remain applied.',
                      )
                    : null,
              ),
          ],
        ),
        if (!busy && vm.setupComplete) ...[
          if (vm.ssh != null)
            CredentialsCard(title: 'SSH access', details: vm.ssh!),
          if (vm.socks != null)
            CredentialsCard(title: 'SOCKS5 access', details: vm.socks!),
          if (changeRoot)
            CredentialsCard(
              title: 'New root password',
              details: ConnectionDetails(
                host: vm.ssh!.host,
                port: vm.ssh!.port,
                user: 'root',
                password: rootPassword.text,
              ),
            ),
          SectionCard(
            title: 'Allow these ports in your hosting panel',
            children: [
              Text('TCP ${vm.ssh?.port} · SSH'),
              if (installAwg)
                Text(
                  'UDP ${vm.server['awg_port'] ?? awgPort.text} · AmneziaWG',
                ),
              if (installSocks)
                Text('TCP ${vm.socks?.port ?? socksPort.text} · SOCKS5'),
              if (installVless)
                Text(
                  'TCP ${vm.server['vless_port'] ?? vlessPort.text} · VLESS + Reality',
                ),
              if (!installAwg && !installVless)
                const Text(
                  'VPN installation was deferred. SSH credentials are ready for the next step.',
                ),
            ],
          ),
          if (vm.clients.isNotEmpty)
            SectionCard(
              title: 'Your VPN clients',
              children: [
                for (final client in vm.clients)
                  ListTile(
                    title: Text(client['name'].toString()),
                    subtitle: Text(
                      vpnSourceLabel(client['source'] as String? ?? 'Host'),
                    ),
                    trailing: OutlinedButton(
                      onPressed: client['can_export'] == false
                          ? null
                          : () => exportClient(
                              context,
                              vm,
                              client['name'].toString(),
                              source: client['source'] as String?,
                              publicKey: client['public_key'] as String?,
                            ),
                      child: const Text('Get configuration'),
                    ),
                  ),
              ],
            ),
        ],
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
    ),
  };
  Widget _review(String label, bool value, {String? detail}) => Padding(
    padding: const EdgeInsets.only(top: 12),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(
          value ? Icons.check_circle_outline : Icons.remove_circle_outline,
          size: 20,
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Text(
            '$label: ${value ? 'Yes' : 'No'}${value && detail != null && detail.isNotEmpty ? ' · $detail' : ''}',
          ),
        ),
      ],
    ),
  );

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: vm,
    builder: (context, _) => PopScope(
      canPop: !busy,
      child: Scaffold(
        appBar: AppBar(
          title: Text(
            widget.editTemplate
                ? 'Template · ${name.text.isEmpty ? 'New' : name.text}'
                : 'Set up a server',
          ),
        ),
        body: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 840),
            child: Column(
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(24, 8, 24, 16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Step ${step + 1} of ${widget.editTemplate ? 6 : 7} · ${labels[step]}',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 12),
                      LinearProgressIndicator(
                        value: (step + 1) / (widget.editTemplate ? 6 : 7),
                      ),
                    ],
                  ),
                ),
                Expanded(
                  child: SingleChildScrollView(
                    padding: const EdgeInsets.symmetric(horizontal: 24),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        if (localError.isNotEmpty || vm.error.isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.only(bottom: 16),
                            child: Semantics(
                              liveRegion: true,
                              child: Text(
                                localError.isNotEmpty ? localError : vm.error,
                                style: TextStyle(
                                  color: Theme.of(context).colorScheme.error,
                                ),
                              ),
                            ),
                          ),
                        content(),
                      ],
                    ),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(24),
                  child: Row(
                    children: [
                      if (step > 0 && step < 6)
                        OutlinedButton(
                          onPressed: busy
                              ? null
                              : () => setState(() {
                                  step--;
                                  localError = '';
                                }),
                          child: const Text('Back'),
                        ),
                      const Spacer(),
                      if (step < 5)
                        FilledButton(
                          onPressed: busy ? null : next,
                          child: Text(
                            step == 0 &&
                                    !widget.editTemplate &&
                                    !widget.useConnected
                                ? 'Connect and continue'
                                : 'Continue',
                          ),
                        ),
                      if (step == 5)
                        FilledButton(
                          onPressed: busy ? null : run,
                          child: Text(
                            widget.editTemplate ? 'Save template' : 'Run setup',
                          ),
                        ),
                      if (step == 6 && !busy && !vm.setupComplete)
                        OutlinedButton(
                          onPressed: () => setState(() => step = 5),
                          child: const Text('Review answers'),
                        ),
                      if (step == 6 && !busy) ...[
                        const SizedBox(width: 8),
                        FilledButton(
                          onPressed: () => Navigator.pop(context, true),
                          child: const Text('Open server'),
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    ),
  );
}
