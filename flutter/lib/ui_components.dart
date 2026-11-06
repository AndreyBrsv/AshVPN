import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'workspace_controller.dart';
import 'vless_connection.dart';
import 'vless_export_dialog.dart';
import 'client_configuration.dart';
import 'private_export.dart';
import 'private_qr.dart';
import 'amnezia_connection.dart';

class SectionCard extends StatelessWidget {
  const SectionCard({
    super.key,
    required this.title,
    this.subtitle,
    required this.children,
  });
  final String title;
  final String? subtitle;
  final List<Widget> children;
  @override
  Widget build(BuildContext context) => Card(
    margin: const EdgeInsets.only(bottom: 16),
    child: Padding(
      padding: EdgeInsets.all(MediaQuery.sizeOf(context).width < 900 ? 16 : 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: Theme.of(context).textTheme.titleLarge),
          if (subtitle != null) ...[
            const SizedBox(height: 8),
            Text(
              subtitle!,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
          const SizedBox(height: 16),
          ...children,
        ],
      ),
    ),
  );
}

class SecretField extends StatefulWidget {
  const SecretField({
    super.key,
    required this.controller,
    required this.label,
    this.enabled = true,
    this.helper,
  });
  final TextEditingController controller;
  final String label;
  final bool enabled;
  final String? helper;
  @override
  State<SecretField> createState() => _SecretFieldState();
}

class _SecretFieldState extends State<SecretField> {
  bool reveal = false;
  @override
  Widget build(BuildContext context) => TextFormField(
    controller: widget.controller,
    enabled: widget.enabled,
    obscureText: !reveal,
    autocorrect: false,
    enableSuggestions: false,
    decoration: InputDecoration(
      labelText: widget.label,
      helperText: widget.helper,
      suffixIcon: ListenableBuilder(
        listenable: widget.controller,
        builder: (context, _) => Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (widget.controller.text.isNotEmpty)
              IconButton(
                tooltip: 'Clear password',
                onPressed: widget.enabled ? widget.controller.clear : null,
                icon: const Icon(Icons.close),
              ),
            IconButton(
              tooltip: reveal ? 'Hide password' : 'Show password',
              onPressed: widget.enabled
                  ? () => setState(() => reveal = !reveal)
                  : null,
              icon: Icon(
                reveal
                    ? Icons.visibility_off_outlined
                    : Icons.visibility_outlined,
              ),
            ),
          ],
        ),
      ),
    ),
  );
}

Future<bool> confirmAction(
  BuildContext context,
  String title,
  String description, {
  String action = 'Continue',
}) async =>
    await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        scrollable: true,
        title: Text(title),
        content: Text(description),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(action),
          ),
        ],
      ),
    ) ??
    false;

Future<bool> confirmServerKey(
  BuildContext context,
  String type,
  String fingerprint,
) async =>
    await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        scrollable: true,
        title: const Text('Verify server key'),
        content: SelectableText(
          'Compare this fingerprint with your hosting provider:\n\n$type\n$fingerprint\n\nTrust this server key?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Trust'),
          ),
        ],
      ),
    ) ??
    false;

class ChangedServerKeyAction extends StatelessWidget {
  const ChangedServerKeyAction({super.key, required this.controller});

  final WorkspaceController controller;

  @override
  Widget build(BuildContext context) {
    final change = controller.changedHostKey;
    if (change == null) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: OutlinedButton.icon(
        icon: const Icon(Icons.fingerprint),
        label: const Text('Review changed server key'),
        onPressed: controller.busy
            ? null
            : () async {
                final accepted = await showDialog<bool>(
                  context: context,
                  builder: (context) => AlertDialog(
                    scrollable: true,
                    title: const Text('SSH server key changed'),
                    content: SelectableText(
                      'Server: ${change.endpoint}\n\n'
                      'Previously trusted:\n${change.previousKey}\n\n'
                      'New key:\n${change.replacementKey}\n\n'
                      'A server reinstall can change this key. Confirm the new fingerprint '
                      'through your hosting provider or another connection you already trust '
                      'before replacing it.',
                    ),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(context, false),
                        child: const Text('Cancel'),
                      ),
                      FilledButton(
                        onPressed: () => Navigator.pop(context, true),
                        child: const Text('Trust new key'),
                      ),
                    ],
                  ),
                );
                if (accepted != true || !context.mounted) return;
                if (await controller.acceptChangedHostKey(change) &&
                    context.mounted) {
                  showNotice(context, 'Server key updated. Connect again.');
                }
              },
      ),
    );
  }
}

void showNotice(BuildContext context, String message) {
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
}

Future<void> copyClientValue(
  BuildContext context,
  String value,
  String notice,
) async {
  try {
    await Clipboard.setData(ClipboardData(text: value));
    if (context.mounted) {
      showNotice(context, notice);
    }
  } catch (_) {
    if (context.mounted) {
      showNotice(
        context,
        'Could not copy to the clipboard. Try saving a file instead.',
      );
    }
  }
}

Future<void> copyClientConnection(
  BuildContext context,
  WorkspaceController controller,
  String name, {
  String? source,
  String? publicKey,
}) async {
  final String? content;
  if (source == VlessConnection.source) {
    content = (await controller.vlessConnection(name, publicKey ?? ''))?.link;
  } else {
    final config = await controller.clientConfig(
      name,
      source: source,
      publicKey: publicKey,
    );
    if (config == null || !context.mounted) return;
    try {
      content = AmneziaConnection.fromConfig(name, config).link;
    } on FormatException catch (error) {
      if (context.mounted) showNotice(context, error.message);
      return;
    }
  }
  if (!context.mounted || content == null) return;
  await copyClientValue(
    context,
    content,
    'Connection copied. Keep it private.',
  );
}

Future<void> exportClient(
  BuildContext context,
  WorkspaceController controller,
  String name, {
  String? source,
  String? publicKey,
  bool showQr = false,
}) async {
  final endpoint = '${controller.ssh!.host}:${controller.ssh!.port}';
  if (source == VlessConnection.source) {
    final connection = await controller.vlessConnection(name, publicKey ?? '');
    if (!context.mounted || connection == null) return;
    await showDialog<void>(
      context: context,
      builder: (_) => VlessExportDialog(
        connection: connection,
        endpoint: endpoint,
        initialQr: showQr,
      ),
    );
    return;
  }
  final config = await controller.clientConfig(
    name,
    source: source,
    publicKey: publicKey,
  );
  if (!context.mounted || config == null) return;
  await showDialog<void>(
    context: context,
    builder: (_) => ClientExportDialog(
      name: name,
      config: config,
      initialQr: showQr,
      endpoint: '$endpoint${source == null ? '' : ' · $source'}',
    ),
  );
}

class ClientExportDialog extends StatefulWidget {
  const ClientExportDialog({
    super.key,
    required this.name,
    required this.config,
    this.endpoint = '',
    this.initialQr = false,
  });
  final String name, config;
  final String endpoint;
  final bool initialQr;
  @override
  State<ClientExportDialog> createState() => _ClientExportDialogState();
}

class _ClientExportDialogState extends State<ClientExportDialog> {
  bool saving = false;
  late bool qr = widget.initialQr;
  AmneziaConnection? amnezia;
  String? linkError;
  bool useLink = false;
  int revision = 0;

  @override
  void initState() {
    super.initState();
    readFormats();
  }

  void readFormats() {
    revision++;
    try {
      amnezia = AmneziaConnection.fromConfig(widget.name, widget.config);
      linkError = null;
    } on FormatException catch (error) {
      amnezia = null;
      linkError = error.message;
    }
    qr = widget.initialQr;
    useLink = amnezia != null && !qr;
  }

  String get content => useLink ? amnezia!.link : widget.config;

  @override
  void didUpdateWidget(covariant ClientExportDialog oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.config != widget.config ||
        oldWidget.endpoint != widget.endpoint ||
        oldWidget.name != widget.name) {
      readFormats();
    }
  }

  Future<void> save() async {
    final value = content;
    final extension = useLink ? 'vpn' : 'conf';
    setState(() => saving = true);
    try {
      final result = await getSaveLocation(
        suggestedName:
            '${'${widget.name}-${widget.endpoint}'.replaceAll(RegExp(r'[^A-Za-z0-9_-]'), '_')}.$extension',
      );
      if (result == null) return;
      await savePrivateExport(result.path, value);
      if (mounted) showNotice(context, 'Configuration saved. Keep it private.');
    } catch (_) {
      if (mounted) {
        showNotice(
          context,
          'Could not save the configuration. Choose another location.',
        );
      }
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    scrollable: true,
    title: Text('VPN access · ${widget.name}\n${widget.endpoint}'),
    content: SizedBox(
      width: 540,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'This is the saved configuration of this existing client. Opening, copying or showing its QR code does not create or rotate any key.',
          ),
          const SizedBox(height: 16),
          DropdownButtonFormField<bool>(
            key: ValueKey(revision),
            initialValue: useLink,
            decoration: const InputDecoration(labelText: 'Export format'),
            isExpanded: true,
            items: [
              DropdownMenuItem(
                value: true,
                enabled: amnezia != null,
                child: const Text('AmneziaVPN link (vpn://)'),
              ),
              const DropdownMenuItem(
                value: false,
                child: Text('Native configuration (.conf)'),
              ),
            ],
            onChanged: saving
                ? null
                : (value) {
                    if (value == null || (value && amnezia == null)) return;
                    setState(() {
                      useLink = value;
                      if (value) qr = false;
                    });
                  },
          ),
          const SizedBox(height: 12),
          if (useLink)
            const Text(
              'In AmneziaVPN, choose + and paste the copied key. This gives one device VPN access. It does not add SSH administration in AmneziaVPN. Manage this client in Ashapp.',
            ),
          if (linkError != null)
            Text(linkError!, style: Theme.of(context).textTheme.bodySmall),
          Row(
            children: [
              Expanded(
                child: Text(
                  useLink ? 'AmneziaVPN link' : 'Client configuration',
                ),
              ),
              IconButton.filledTonal(
                tooltip: useLink ? 'Copy Amnezia link' : 'Copy configuration',
                onPressed: saving
                    ? null
                    : () => copyClientValue(
                        context,
                        content,
                        useLink
                            ? 'Amnezia link copied. Paste it in AmneziaVPN.'
                            : 'Configuration copied, including its original private key.',
                      ),
                icon: const Icon(Icons.copy),
              ),
            ],
          ),
          if (ClientConfiguration(widget.config).privateKey
              case final String key)
            Row(
              children: [
                const Expanded(child: Text('Private key')),
                IconButton(
                  tooltip: 'Copy private key',
                  onPressed: saving
                      ? null
                      : () => copyClientValue(
                          context,
                          key,
                          'Private key copied. Keep it secret.',
                        ),
                  icon: const Icon(Icons.copy),
                ),
              ],
            ),
          const SizedBox(height: 8),
          if (!useLink)
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton(
                  onPressed: () => setState(() => qr = !qr),
                  child: Text(qr ? 'Hide QR code' : 'Show QR code'),
                ),
              ],
            ),
          if (qr)
            Center(
              // Bound both axes before qr_flutter's LayoutBuilder. The
              // scrolling dialog measures its content's intrinsic height.
              child: SizedBox.square(
                dimension: (MediaQuery.sizeOf(context).width - 128).clamp(
                  1.0,
                  420.0,
                ),
                child: PrivateQr(
                  data: widget.config,
                  label:
                      'Private configuration QR code for this existing client',
                  fallback: 'This configuration is too large for a QR code. Copy it or save the .conf file instead. No key was changed.',
                ),
              ),
            ),
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: saving ? null : () => Navigator.pop(context),
        child: const Text('Close'),
      ),
      FilledButton(
        onPressed: saving ? null : save,
        child: Text(useLink ? 'Save .vpn' : 'Save .conf'),
      ),
    ],
  );
}
