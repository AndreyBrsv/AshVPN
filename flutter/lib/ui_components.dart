import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'workspace_controller.dart';
import 'vless_connection.dart';
import 'vless_export_dialog.dart';
import 'client_configuration.dart';
import 'private_export.dart';
import 'private_qr.dart';

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
      suffixIcon: IconButton(
        tooltip: reveal ? 'Hide password' : 'Show password',
        onPressed: widget.enabled
            ? () => setState(() => reveal = !reveal)
            : null,
        icon: Icon(
          reveal ? Icons.visibility_off_outlined : Icons.visibility_outlined,
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
    content = await controller.clientConfig(
      name,
      source: source,
      publicKey: publicKey,
    );
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

  @override
  void didUpdateWidget(covariant ClientExportDialog oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.config != widget.config ||
        oldWidget.endpoint != widget.endpoint ||
        oldWidget.name != widget.name) {
      qr = widget.initialQr;
    }
  }

  Future<void> save() async {
    setState(() => saving = true);
    try {
      final result = await getSaveLocation(
        suggestedName:
            '${'${widget.name}-${widget.endpoint}'.replaceAll(RegExp(r'[^A-Za-z0-9_-]'), '_')}.conf',
      );
      if (result == null) return;
      await savePrivateExport(result.path, widget.config);
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
    title: Text('VPN access · ${widget.name}\n${widget.endpoint}'),
    content: SizedBox(
      width: 540,
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'This is the saved configuration of this existing client. Opening, copying or showing its QR code does not create or rotate any key.',
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                const Expanded(child: Text('Client configuration')),
                IconButton.filledTonal(
                  tooltip: 'Copy configuration',
                  onPressed: saving
                      ? null
                      : () => copyClientValue(
                          context,
                          widget.config,
                          'Configuration copied, including its original private key.',
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
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 420),
                  child: AspectRatio(
                    aspectRatio: 1,
                    child: PrivateQr(
                      data: widget.config,
                      label: 'Private configuration QR code for this existing client',
                      fallback: 'This configuration is too large for a QR code. Copy it or save the .conf file instead. No key was changed.',
                    ),
                  ),
                ),
              ),
          ],
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: saving ? null : () => Navigator.pop(context),
        child: const Text('Close'),
      ),
      FilledButton(
        onPressed: saving ? null : save,
        child: const Text('Save .conf'),
      ),
    ],
  );
}
