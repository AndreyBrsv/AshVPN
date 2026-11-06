import 'package:flutter/material.dart';

import 'connection_details.dart';
import 'credentials_card.dart';
import 'server_template.dart';
import 'setup_secrets.dart';
import 'ui_components.dart';
import 'workspace_controller.dart';
import 'vless_connection.dart';
import 'operation_progress.dart';
import 'private_key_field.dart';
import 'activity_console.dart';

/// Manual setup and templates edit the same questions and execute one plan.
class SetupWizard extends StatefulWidget {
  const SetupWizard({
    super.key,
    required this.controller,
    this.editTemplate = false,
    this.useConnected = false,
    this.initial,
    this.secrets = const SetupSecrets(),
    this.resumeRunId,
  });
  final WorkspaceController controller;
  final bool editTemplate, useConnected;
  final ServerTemplate? initial;
  final SetupSecrets secrets;
  final String? resumeRunId;
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
  final privateKey = TextEditingController(),
      keyPassphrase = TextEditingController();
  bool keyLogin = false, generateKey = false;
  bool protectSsh = true,
      configureFirewall = true,
      automaticUpdates = false,
      disablePasswords = false;
  String socksAccess = 'public';
  String awgDeployment = ServerTemplate.defaultAwgDeployment;
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
  void _resetConnectionCredentials() {
    login.text = 'root';
    loginPassword.clear();
    keyLogin = false;
  }

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
      if (!widget.editTemplate && !widget.useConnected) {
        _resetConnectionCredentials();
      }
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
      if (privateKey.text.isEmpty && widget.resumeRunId == null) {
        privateKey.text = vm.ssh!.privateKey;
        keyPassphrase.text = vm.ssh!.keyPassphrase;
      }
      keyLogin = vm.ssh!.usesKey;
      if (widget.initial == null) {
        protectSsh =
            (vm.security?['fail2ban'] as Map?)?['managed'] == true &&
            (vm.security?['fail2ban'] as Map?)?['enabled'] == true;
        configureFirewall = vm.managesFirewall;
        automaticUpdates =
            (vm.security?['automatic_updates'] as Map?)?['managed'] == true &&
            (vm.security?['automatic_updates'] as Map?)?['enabled'] == true;
        blockPing = vm.server['icmp_blocked'] == true;
        disableRoot = (vm.server['ssh'] as Map?)?['permitrootlogin'] == 'no';
        disablePasswords =
            (vm.security?['ssh'] as Map?)?['passwordauthentication'] == 'no' &&
            (vm.security?['ssh'] as Map?)?['kbdinteractiveauthentication'] ==
                'no';
        installVless = vm.server['vless'] == true;
        installSocks = vm.server['socks5'] == true;
        if (vm.server['awg_configured'] == true) {
          installAwg = vm.server['awg'] == true;
        }
        if (vm.server['awg_port'] is int) {
          awgPort.text = '${vm.server['awg_port']}';
        }
        if (vm.server['vless_port'] is int) {
          vlessPort.text = '${vm.server['vless_port']}';
        }
        if (vm.server['vless_sni'] is String) {
          realitySni.text = vm.server['vless_sni'] as String;
        }
        if (vm.server['socks5_port'] is int) {
          socksPort.text = '${vm.server['socks5_port']}';
        }
        if (vm.server['socks5_access'] is String) {
          socksAccess = vm.server['socks5_access'] as String;
        }
        final currentDeployment = vm.server['awg_deployment'];
        if (currentDeployment == 'host' || currentDeployment == 'amnezia') {
          awgDeployment = currentDeployment as String;
        }
      }
    }
    if (widget.resumeRunId != null) step = 5;
  }

  void _apply(ServerTemplate item, SetupSecrets secrets) {
    name.text = item.name;
    blockPing = item.blockPing;
    disableRoot = item.disableRoot;
    installAwg = item.installAwg;
    awgDeployment = item.awgDeployment;
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
    protectSsh = item.protectSsh;
    configureFirewall = item.configureFirewall;
    automaticUpdates = item.automaticUpdates;
    disablePasswords = item.disablePasswordLogin;
    generateKey = item.generateSshKey;
    socksAccess = item.socksAccess;
    privateKey.text = secrets.sshPrivateKey;
    keyPassphrase.text = secrets.sshKeyPassphrase;
    keyLogin = privateKey.text.isNotEmpty;
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
      if (privateKey.text.isEmpty && widget.resumeRunId == null) {
        privateKey.text = vm.ssh!.privateKey;
        keyPassphrase.text = vm.ssh!.keyPassphrase;
      }
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
          _resetConnectionCredentials();
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
    awgDeployment: awgDeployment,
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
    protectSsh: protectSsh,
    configureFirewall: configureFirewall,
    automaticUpdates: automaticUpdates,
    disablePasswordLogin: disablePasswords,
    generateSshKey: generateKey,
    socksAccess: socksAccess,
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
    sshPrivateKey: privateKey.text,
    sshKeyPassphrase: keyPassphrase.text,
  );
  String? validateStep() {
    if (step == 0) {
      if (widget.editTemplate) {
        if (name.text.trim().isEmpty || name.text.trim().length > 80) {
          return 'Enter a template name with up to 80 characters.';
        }
      } else if (host.text.trim().isEmpty ||
          login.text.trim().isEmpty ||
          (keyLogin ? privateKey.text.isEmpty : loginPassword.text.isEmpty) ||
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
        if (!widget.editTemplate &&
            vm.needsFirewallRefresh(item) &&
            !item.configureFirewall) {
          return 'Go back to Security and select Configure firewall to refresh its allowlist for the new service.';
        }
        return secrets().validate(
          item,
          activeUser: widget.editTemplate ? null : vm.ssh?.user,
          activeUsesKey: !widget.editTemplate && vm.ssh?.usesKey == true,
          existingSocks:
              !widget.editTemplate && vm.server['socks5_configured'] == true,
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
          privateKey: keyLogin ? privateKey.text : '',
          keyPassphrase: keyPassphrase.text,
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
      if (!await vm.saveTemplate(item, protected.forTemplate()) || !mounted) {
        return;
      }
      if (widget.editTemplate) {
        Navigator.pop(context, true);
        return;
      }
    }
    setState(() {
      step = 6;
      localError = '';
    });
    var resume = widget.resumeRunId;
    if (resume == null && vm.canResumeSetup) {
      final draft = await vm.recoveryDraft();
      if (draft?.matches(item, protected) == true) resume = draft!.runId;
    }
    await vm.provision(item, protected, resumeRunId: resume);
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
      privateKey,
      keyPassphrase,
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
              isExpanded: true,
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
          toggle(
            'Use an SSH key',
            'Authenticate with an imported private key instead of a password.',
            keyLogin,
            (v) => keyLogin = v,
          ),
          if (keyLogin) ...[
            const SizedBox(height: 12),
            PrivateKeyField(
              controller: privateKey,
              enabled: !busy,
              label: 'SSH private key (paste)',
            ),
            const SizedBox(height: 16),
            secret(keyPassphrase, 'Key passphrase (optional)'),
          ],
          if (!keyLogin)
            secret(
              loginPassword,
              widget.editTemplate
                  ? 'Default SSH password (optional)'
                  : 'Password',
            ),
        ],
        if (!widget.editTemplate) ...[
          const SizedBox(height: 12),
          Text(
            vm.operatingSystem['os'] == null
                ? 'OS is detected automatically after connecting. Supported: Ubuntu 22.04/24.04 and Debian 12.'
                : 'Detected OS: ${vm.operatingSystem['os']} ${vm.operatingSystem['version']} · ${vm.operatingSystem['architecture']}',
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
        toggle(
          'Generate a server SSH key',
          'Create a unique key for this server and save it in the OS vault after verifying key login.',
          generateKey,
          (v) => generateKey = v,
        ),
        if (!generateKey && !keyLogin) ...[
          const SizedBox(height: 12),
          PrivateKeyField(
            controller: privateKey,
            enabled: !busy,
            label: 'SSH private key to install (optional)',
          ),
          const SizedBox(height: 16),
          secret(keyPassphrase, 'Private key passphrase (optional)'),
        ],
      ],
    ),
    2 => SectionCard(
      title: 'Security and updates',
      children: [
        toggle(
          'Protect SSH with Fail2ban',
          '5 failures within 10 minutes → block the address for 15 minutes. Existing jails are preserved.',
          protectSsh,
          (v) => protectSsh = v,
        ),
        toggle(
          'Configure firewall',
          'Review and preserve current SSH, service and Docker ports. Required when adding a service behind an existing Ashapp firewall.',
          configureFirewall,
          (v) => configureFirewall = v,
        ),
        toggle(
          'Disable password SSH login',
          'All users. Requires a verified key saved in the OS vault. Off by default.',
          disablePasswords,
          (v) => disablePasswords = v,
        ),
        toggle(
          'Automatic security updates',
          'Distribution security fixes only. No automatic reboot. Off by default.',
          automaticUpdates,
          (v) => automaticUpdates = v,
        ),
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
              'Kernel module only. Choose how to manage the new installation. Existing configurations are preserved.',
              installAwg,
              (v) => installAwg = v,
            ),
            if (installAwg) ...[
              const SizedBox(height: 16),
              Text(
                'AmneziaWG deployment',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              RadioGroup<String>(
                groupValue: awgDeployment,
                onChanged: (value) {
                  if (!busy && value != null) {
                    setState(() => awgDeployment = value);
                  }
                },
                child: Column(
                  children: [
                    RadioListTile<String>(
                      value: 'host',
                      enabled: !busy,
                      contentPadding: EdgeInsets.zero,
                      title: const Text('Host kernel (Ashapp management)'),
                      subtitle: const Text(
                        'Runs directly on Linux. Use Ashapp to manage its clients.',
                      ),
                    ),
                    RadioListTile<String>(
                      value: 'amnezia',
                      enabled: !busy,
                      contentPadding: EdgeInsets.zero,
                      title: const Text('Shared kernel (Ashapp + AmneziaVPN)'),
                      subtitle: const Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Experimental',
                            style: TextStyle(
                              color: Colors.redAccent,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Text(
                            'May not work with your AmneziaVPN version. Requires an x86_64 Linux VPS; discovery and management in the official app are not guaranteed.',
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 12),
              Text(
                awgDeployment == 'amnezia'
                    ? 'Experimental shared compatibility. Use one manager at a time. Reinstalling or upgrading from AmneziaVPN may replace kernel protection; run Ashapp diagnostics afterward.'
                    : 'Import vpn:// device access into AmneziaVPN to connect. Its SSH server manager cannot manage this host installation.',
              ),
              const SizedBox(height: 12),
              const Text(
                'This choice applies to a new installation. Existing deployments are preserved.',
              ),
              const SizedBox(height: 16),
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
                isExpanded: true,
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
              DropdownButtonFormField<String>(
                initialValue: socksAccess,
                isExpanded: true,
                decoration: const InputDecoration(labelText: 'SOCKS5 access'),
                items: const [
                  DropdownMenuItem(
                    value: 'public',
                    child: Text(
                      'Public · current behavior',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  DropdownMenuItem(
                    value: 'private',
                    child: Text(
                      'Private · SSH tunnel',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
                onChanged: busy
                    ? null
                    : (value) => setState(() => socksAccess = value!),
              ),
              const SizedBox(height: 12),
              const Text(
                'Public SOCKS5 password authentication is not encrypted by SOCKS5. Private mode requires stable Docker Engine 28+ and publishes to server loopback; start its tunnel in Manage. A missing daemon is installed during setup; an existing older daemon must be updated separately.',
              ),
              const SizedBox(height: 16),
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
            _review('Protect SSH with Fail2ban', protectSsh),
            _review('Configure firewall', configureFirewall),
            _review('Automatic security updates', automaticUpdates),
            _review('Disable password SSH login', disablePasswords),
            _review('Generate a server SSH key', generateKey),
            _review(
              'Install and verify an imported SSH key',
              !generateKey && privateKey.text.isNotEmpty,
            ),
            _review('Block ping replies', blockPing),
            _review('Update system packages', upgrade),
            if (configureFirewall && !widget.editTemplate) ...[
              const SizedBox(height: 12),
              Text(
                'Existing listening ports to preserve: ${vm.security?['listeners'] ?? 'Inspected before applying'}',
              ),
              Text(
                'Existing Docker publications to preserve: ${vm.security?['docker_ports'] ?? 'Inspected before applying'}',
              ),
              Text(
                'Selected public ports: TCP ${vm.ssh?.port}'
                '${installAwg ? ', UDP ${awgPort.text}' : ''}'
                '${installVless ? ', TCP ${vlessPort.text}' : ''}'
                '${installSocks && socksAccess == 'public' ? ', TCP ${socksPort.text}' : ''}',
              ),
              const Text(
                'Existing firewall policy keeps its precedence. Unsupported external firewalls stop setup; unconfirmed changes roll back after 180 seconds.',
              ),
            ],
            _review(
              'Install AmneziaWG kernel',
              installAwg,
              detail:
                  '${awgDeployment == 'amnezia' ? 'Shared kernel (Ashapp + AmneziaVPN)' : 'Host kernel (Ashapp management)'} · UDP ${awgPort.text} · DNS ${dns.text}',
            ),
            if (installAwg && awgDeployment == 'amnezia')
              const Padding(
                padding: EdgeInsets.only(top: 8),
                child: Text(
                  'Experimental — shared discovery and management may not work with your AmneziaVPN version.',
                  style: TextStyle(
                    color: Colors.redAccent,
                    fontWeight: FontWeight.bold,
                  ),
                ),
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
              detail: 'TCP ${socksPort.text} · $socksAccess',
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
              'Passwords stay masked and are never written into template JSON. Existing VPN/SOCKS5 ports and credentials are preserved. Unchecking a service stops it only when Ashapp owns it; security switches restore the owned baseline. Accounts and passwords change only when selected.',
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
            OperationProgress(controller: vm),
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
        ActivityConsole(controller: vm, initiallyExpanded: true),
        const SizedBox(height: 16),
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
              if (installSocks && socksAccess == 'public')
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
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(client['name'].toString()),
                        Text(
                          vpnSourceLabel(client['source'] as String? ?? 'Host'),
                        ),
                        const SizedBox(height: 8),
                        OutlinedButton(
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
                      ],
                    ),
                  ),
              ],
            ),
        ],
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
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          actions: [
            if (!widget.editTemplate && (vm.connected || vm.log.isNotEmpty))
              IconButton(
                tooltip: 'Server activity',
                onPressed: () => showActivityConsole(context, vm),
                icon: const Icon(Icons.terminal_outlined),
              ),
          ],
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
                        if (widget.resumeRunId != null && step < 6)
                          const Padding(
                            padding: EdgeInsets.only(bottom: 16),
                            child: Text(
                              'Resume the saved plan. Completed password, administrator and SSH-key steps will be kept; services and security are checked again. To change answers, open a new setup wizard.',
                            ),
                          ),
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
                        if (step == 0 && !widget.editTemplate)
                          ChangedServerKeyAction(controller: vm),
                        content(),
                      ],
                    ),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(24),
                  child: OverflowBar(
                    alignment: MainAxisAlignment.end,
                    overflowAlignment: OverflowBarAlignment.end,
                    spacing: 8,
                    overflowSpacing: 8,
                    children: [
                      if (step > 0 && step < 6 && widget.resumeRunId == null)
                        OutlinedButton(
                          onPressed: busy
                              ? null
                              : () => setState(() {
                                  step--;
                                  localError = '';
                                }),
                          child: const Text('Back'),
                        ),
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
