import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';

import 'private_export.dart';
import 'private_qr.dart';
import 'ui_components.dart';
import 'vless_connection.dart';

class VlessExportDialog extends StatefulWidget {
  const VlessExportDialog({
    super.key,
    required this.connection,
    required this.endpoint,
    this.initialQr = false,
  });
  final VlessConnection connection;
  final String endpoint;
  final bool initialQr;
  @override
  State<VlessExportDialog> createState() => _VlessExportDialogState();
}

class _VlessExportDialogState extends State<VlessExportDialog> {
  VlessExportFormat format = VlessExportFormat.link;
  bool saving = false;
  late bool qr = widget.initialQr;

  @override
  void didUpdateWidget(covariant VlessExportDialog oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.connection != widget.connection ||
        oldWidget.endpoint != widget.endpoint) {
      qr = widget.initialQr;
      format = VlessExportFormat.link;
    }
  }

  Future<void> save() async {
    final selected = format;
    final content = widget.connection.export(selected);
    setState(() => saving = true);
    try {
      final filename =
          '${widget.connection.name}-${widget.connection.address}-${selected.name}'
              .replaceAll(RegExp(r'[^A-Za-z0-9_-]'), '_');
      final location = await getSaveLocation(
        suggestedName: '$filename.${selected.extension}',
      );
      if (location != null) {
        await savePrivateExport(location.path, content);
        if (mounted) showNotice(context, 'Connection saved. Keep it private.');
      }
    } catch (_) {
      if (mounted) {
        showNotice(
          context,
          'Could not save the connection. Choose another location.',
        );
      }
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text('VLESS access · ${widget.connection.name}\n${widget.endpoint}'),
    content: SizedBox(
      width: 540,
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'All formats use this existing device UUID. Anyone with the link or QR can use its access.',
            ),
            const SizedBox(height: 16),
            DropdownButtonFormField<VlessExportFormat>(
              key: ValueKey((widget.connection, widget.endpoint)),
              initialValue: format,
              isExpanded: true,
              decoration: const InputDecoration(labelText: 'Export format'),
              items: [
                for (final item in VlessExportFormat.values)
                  DropdownMenuItem(value: item, child: Text(item.label)),
              ],
              onChanged: saving
                  ? null
                  : (value) {
                      if (value != null) {
                        setState(() {
                          format = value;
                        });
                      }
                    },
            ),
            const SizedBox(height: 16),
            Text(
              format == VlessExportFormat.link
                  ? 'Import into a client supporting VLESS + Reality + XTLS Vision.'
                  : 'Standalone core config: local proxy on 127.0.0.1:10808. It does not enable a system VPN. Validated target: ${format == VlessExportFormat.xray ? 'Xray 26.10.31' : 'sing-box 1.14.4'}. GUI apps may expect a link instead.',
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                const Expanded(child: Text('Client connection')),
                IconButton.filledTonal(
                  tooltip: 'Copy connection',
                  onPressed: saving
                      ? null
                      : () => copyClientValue(
                          context,
                          widget.connection.export(format),
                          'Connection copied. Keep it private.',
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
            if (qr) ...[
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 16),
                child: Text(
                  'The QR always contains the VLESS link, including when a JSON format is selected.',
                ),
              ),
              Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 420),
                  child: AspectRatio(
                    aspectRatio: 1,
                    child: PrivateQr(
                      data: widget.connection.link,
                      label: 'VLESS link QR code for this existing device',
                      fallback: 'The link is too large for QR. Copy or save it instead.',
                    ),
                  ),
                ),
              ),
            ],
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
        child: const Text('Save file'),
      ),
    ],
  );
}
