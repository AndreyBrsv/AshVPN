import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'connection_details.dart';

class CredentialsCard extends StatefulWidget {
  const CredentialsCard({
    super.key,
    required this.title,
    required this.details,
  });
  final String title;
  final ConnectionDetails details;

  @override
  State<CredentialsCard> createState() => _CredentialsCardState();
}

class _CredentialsCardState extends State<CredentialsCard> {
  bool _revealed = false;

  @override
  void didUpdateWidget(CredentialsCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(oldWidget.details, widget.details)) _revealed = false;
  }

  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(widget.title, style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 12),
          SelectableText(widget.details.format(revealPassword: _revealed)),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            children: [
              TextButton.icon(
                onPressed: () => setState(() => _revealed = !_revealed),
                icon: Icon(_revealed ? Icons.visibility_off : Icons.visibility),
                label: Text(_revealed ? 'Hide password' : 'Show password'),
              ),
              TextButton.icon(
                onPressed: () async {
                  await Clipboard.setData(
                    ClipboardData(
                      text: widget.details.format(revealPassword: true),
                    ),
                  );
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text(
                          'Connection details copied, including the password.',
                        ),
                      ),
                    );
                  }
                },
                icon: const Icon(Icons.copy),
                label: const Text('Copy connection details'),
              ),
            ],
          ),
        ],
      ),
    ),
  );
}
