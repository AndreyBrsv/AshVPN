import 'package:flutter/material.dart';

import 'operation_progress.dart';
import 'ui_components.dart';
import 'workspace_controller.dart';
import 'private_key_field.dart';

/// Draft controls do not mutate a server until its preview is confirmed.
class SecurityPanel extends StatefulWidget {
  const SecurityPanel({super.key, required this.controller});
  final WorkspaceController controller;
  @override
  State<SecurityPanel> createState() => _SecurityPanelState();
}

class _SecurityPanelState extends State<SecurityPanel> {
  final changes = <String, bool>{};
  final privateKey = TextEditingController(),
      passphrase = TextEditingController();
  bool localBusy = false;
  WorkspaceController get vm => widget.controller;
  bool get busy => vm.busy || localBusy;

  @override
  void didUpdateWidget(SecurityPanel oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(oldWidget.controller, vm)) {
      changes.clear();
      privateKey.clear();
      passphrase.clear();
    }
  }

  @override
  void dispose() {
    privateKey.dispose();
    passphrase.dispose();
    super.dispose();
  }

  Widget option(String key, String title, String description, bool? current) =>
      CheckboxListTile(
        contentPadding: EdgeInsets.zero,
        tristate: current == null,
        title: Text(title),
        subtitle: Text(
          current == null
              ? 'Unknown. Run diagnostics before changing this setting.'
              : description,
        ),
        value: changes[key] ?? current,
        onChanged: busy || current == null
            ? null
            : (value) => setState(() {
                if (value == current) {
                  changes.remove(key);
                } else {
                  changes[key] = value!;
                }
              }),
      );

  Future<void> apply() async {
    final target = vm;
    final selected = Map<String, bool>.of(changes);
    setState(() => localBusy = true);
    try {
      final plan = await target.previewSecurity(selected);
      if (plan == null || !mounted) return;
      final ports = plan['ports'] as Map? ?? {};
      if (!await confirmAction(
        context,
        'Apply security changes?',
        'Server ${target.ssh!.host}:${target.ssh!.port}\n'
            '${selected.entries.map((e) => '${e.key}: ${e.value ? 'On' : 'Off'}').join('\n')}\n\n'
            'Preserved TCP ports: ${ports['tcp']}\nPreserved UDP ports: ${ports['udp']}\n'
            '${plan['notice']}\n\n'
            'Turning protection off removes Ashapp settings. External policy may remain active. '
            'Enabling root/password access makes those SSH login methods available again.',
      )) {
        return;
      }
      if (await target.applySecurity(selected, plan['digest'] as String) &&
          mounted) {
        setState(changes.clear);
      }
    } finally {
      if (mounted) setState(() => localBusy = false);
    }
  }

  Future<void> installKey(bool generate) async {
    final target = vm;
    if (!await confirmAction(
      context,
      generate ? 'Generate a server SSH key?' : 'Install this SSH key?',
      'Save the private key in the OS credential vault, install its public key for '
      '${target.ssh!.user} on ${target.ssh!.host}:${target.ssh!.port}, and verify a new key login and sudo. '
      'Password login remains unchanged. ${target.socksTunnel != null ? 'The private SOCKS5 tunnel will stop when the SSH session changes.' : ''}',
    )) {
      return;
    }
    if (await target.installSshIdentity(
          privateKey.text,
          passphrase.text,
          generate: generate,
        ) &&
        mounted) {
      privateKey.clear();
      passphrase.clear();
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    final data = vm.security;
    final ssh = data?['ssh'] as Map?;
    final fail2ban = data?['fail2ban'] as Map?;
    final firewall = data?['firewall'] as Map?;
    final updates = data?['automatic_updates'] as Map?;
    return SectionCard(
      title: 'Security',
      subtitle: 'Settings for ${vm.ssh!.host}:${vm.ssh!.port}',
      children: [
        OutlinedButton.icon(
          onPressed: busy
              ? null
              : () async {
                  final target = vm;
                  if (await target.diagnoseSecurity() && mounted) {
                    setState(changes.clear);
                  }
                },
          icon: const Icon(Icons.health_and_safety_outlined),
          label: const Text('Run diagnostics'),
        ),
        if (vm.securityError.isNotEmpty) Text(vm.securityError),
        if (data?['pending'] == true)
          const Text(
            'A security change is pending confirmation or rollback. Do not close recovery access.',
          ),
        for (final warning in data?['warnings'] as List? ?? [])
          Text(warning.toString()),
        option(
          'fail2ban',
          'Protect SSH with Fail2ban',
          'Ashapp SSH jail · 5 failures / 10 minutes · 15-minute ban. Other jails remain unchanged.',
          fail2ban?['enabled'] as bool?,
        ),
        if (fail2ban?['error'] != null) Text(fail2ban!['error'].toString()),
        option(
          'firewall',
          'Firewall protection',
          'Preserve existing ports and policy. Disabling removes only Ashapp firewall rules.',
          firewall?['enabled'] as bool?,
        ),
        option(
          'automatic_updates',
          'Automatic security updates',
          'Distribution security fixes. No automatic reboot. External update policy is preserved when Ashapp settings are removed.',
          updates == null
              ? null
              : updates['managed'] == true
              ? (updates['enabled'] as bool?)
              : false,
        ),
        if (updates != null)
          Text(
            'Effective automatic OS updates: ${updates['enabled'] ?? 'Unknown'} · automatic reboot: ${updates['automatic_reboot'] ?? 'Unknown'}',
          ),
        option(
          'disable_root',
          'Disable root SSH login',
          'Applies to all root SSH login methods. Turning off explicitly permits root SSH again.',
          ssh == null ? null : ssh['permitrootlogin'] == 'no',
        ),
        option(
          'disable_passwords',
          'Disable password SSH login',
          'All users. Requires a verified SSH key saved in the OS vault. Turning off allows password login again.',
          ssh == null
              ? null
              : ssh['passwordauthentication'] == 'no' &&
                    ssh['kbdinteractiveauthentication'] == 'no',
        ),
        FilledButton(
          onPressed: busy || changes.isEmpty ? null : apply,
          child: const Text('Review and apply changes'),
        ),
        if (data?['listeners'] != null)
          Text(
            'Listening ports (reachability depends on firewall): ${data!['listeners']}',
          ),
        if (data?['docker_ports'] != null &&
            (data!['docker_ports'] as List).isNotEmpty)
          Text('Docker published ports: ${data['docker_ports']}'),
        if (data?['reboot_required'] == true)
          const Text(
            'A server reboot is required. Ashapp will not reboot automatically.',
          ),
        if ((fail2ban?['banned'] as List? ?? []).isNotEmpty) ...[
          const Divider(),
          const Text('Blocked by the Ashapp SSH jail'),
          for (final address in fail2ban!['banned'] as List)
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(address.toString()),
              trailing: TextButton(
                onPressed: busy
                    ? null
                    : () async {
                        final target = vm;
                        if (await confirmAction(
                          context,
                          'Unblock address?',
                          '$address · ${target.ssh!.host}:${target.ssh!.port}',
                        )) {
                          await target.unbanAddress(address.toString());
                        }
                      },
                child: const Text('Unblock'),
              ),
            ),
        ],
        const Divider(),
        const Text('SSH key access'),
        const Text(
          'A generated key is unique to this server. Imported keys and passphrases stay in the OS vault.',
        ),
        OutlinedButton(
          onPressed: busy ? null : () => installKey(true),
          child: const Text('Generate and install SSH key'),
        ),
        PrivateKeyField(
          controller: privateKey,
          enabled: !busy,
          label: 'Import SSH private key (paste)',
        ),
        SecretField(
          controller: passphrase,
          label: 'Key passphrase (optional)',
          enabled: !busy,
        ),
        OutlinedButton(
          onPressed: busy ? null : () => installKey(false),
          child: const Text('Import and verify SSH key'),
        ),
        OperationProgress(controller: vm),
      ],
    );
  }
}
