import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Paste through a dedicated action: single-line editable fields strip PEM newlines.
class PrivateKeyField extends StatelessWidget {
  const PrivateKeyField({
    super.key,
    required this.controller,
    required this.label,
    this.enabled = true,
  });
  final TextEditingController controller;
  final String label;
  final bool enabled;

  Future<void> _paste(BuildContext context) async {
    try {
      final data = await Clipboard.getData(Clipboard.kTextPlain);
      final text = data?.text;
      if (!context.mounted || text == null) return;
      if (text.length > 32768 || text.contains('\x00')) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Paste one SSH private key, up to 32 KiB.'),
          ),
        );
        return;
      }
      // Preserve header, body and footer exactly; never render the private bytes.
      controller.text = text;
    } catch (_) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('The clipboard could not be read.')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      ExcludeSemantics(
        child: Text(label, style: Theme.of(context).textTheme.bodyMedium),
      ),
      const SizedBox(height: 8),
      Semantics(
        label: label,
        child: TextField(
          controller: controller,
          enabled: enabled,
          readOnly: true,
          obscureText: true,
          autocorrect: false,
          enableSuggestions: false,
          enableInteractiveSelection: false,
          decoration: InputDecoration(
            helperText: 'Use Paste to preserve the original key format.',
            helperMaxLines: 8,
            suffixIcon: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                IconButton(
                  tooltip: 'Paste SSH private key',
                  style: IconButton.styleFrom(minimumSize: const Size(48, 48)),
                  onPressed: enabled ? () => _paste(context) : null,
                  icon: const Icon(Icons.content_paste),
                ),
                IconButton(
                  tooltip: 'Clear SSH private key',
                  style: IconButton.styleFrom(minimumSize: const Size(48, 48)),
                  onPressed: enabled ? controller.clear : null,
                  icon: const Icon(Icons.clear),
                ),
              ],
            ),
          ),
        ),
      ),
    ],
  );
}
