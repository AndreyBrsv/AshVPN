import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'client_configuration.dart';

class ImportedClientConfiguration {
  const ImportedClientConfiguration(this.content, this.replace);
  final String content;
  final bool replace;
}

class ImportClientDialog extends StatefulWidget {
  const ImportClientDialog({
    super.key,
    required this.endpoint,
    required this.name,
  });
  final String endpoint, name;
  @override
  State<ImportClientDialog> createState() => _ImportClientDialogState();
}

class _ImportClientDialogState extends State<ImportClientDialog> {
  String configuration = '';
  bool replace = false, loading = false;
  String error = '';

  Future<void> load(bool clipboard) async {
    setState(() {
      loading = true;
      error = '';
    });
    try {
      String? content;
      if (clipboard) {
        content = (await Clipboard.getData(Clipboard.kTextPlain))?.text;
      } else {
        final file = await openFile(
          acceptedTypeGroups: [
            const XTypeGroup(label: 'VPN configuration', extensions: ['conf']),
          ],
        );
        if (file == null) return;
        if (await file.length() > ClientConfiguration.maxBytes) {
          throw const FormatException();
        }
        content = await file.readAsString();
      }
      if (!mounted) return;
      if (content == null || !ClientConfiguration(content).withinLimit) {
        setState(
          () => error = 'Choose a .conf file or paste a configuration no larger than 128 KiB.',
        );
        return;
      }
      setState(() => configuration = content!);
    } catch (_) {
      if (mounted) {
        setState(
          () => error = 'The configuration could not be read. Choose a UTF-8 .conf file no larger than 128 KiB.',
        );
      }
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    scrollable: true,
    title: Text('Import existing access · ${widget.name}'),
    content: SizedBox(
      width: 560,
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.endpoint),
            const SizedBox(height: 12),
            const Text(
              'Choose the original client .conf. Its private key must match this client. Saving this copy does not create a new key or change VPN access.',
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton(
                  onPressed: loading ? null : () => load(false),
                  child: const Text('Choose .conf'),
                ),
                OutlinedButton(
                  onPressed: loading ? null : () => load(true),
                  child: const Text('Paste configuration'),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text(
              configuration.isEmpty
                  ? 'No configuration selected.'
                  : 'Private configuration loaded and hidden.',
            ),
            CheckboxListTile(
              value: replace,
              contentPadding: EdgeInsets.zero,
              onChanged: loading
                  ? null
                  : (value) => setState(() => replace = value ?? false),
              title: const Text('Replace saved copy'),
              subtitle: const Text(
                'Only the stored configuration is replaced. The VPN peer and its key stay the same.',
              ),
            ),
            if (error.isNotEmpty) Text(error, semanticsLabel: error),
          ],
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: loading ? null : () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(
        onPressed: loading
            ? null
            : () {
                final config = ClientConfiguration(configuration);
                if (!config.withinLimit || config.privateKey == null) {
                  setState(
                    () => error = 'Import a full .conf containing its original private key. Export vpn:// links to .conf in the original app first.',
                  );
                  return;
                }
                Navigator.pop(
                  context,
                  ImportedClientConfiguration(configuration, replace),
                );
              },
        child: const Text('Save existing configuration'),
      ),
    ],
  );
}
