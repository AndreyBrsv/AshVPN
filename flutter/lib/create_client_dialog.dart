import 'dart:io';

import 'package:flutter/material.dart';

import 'vless_connection.dart';

class ClientDraft {
  const ClientDraft(this.name, this.source, this.dns);
  final String name, source, dns;
}

class CreateClientDialog extends StatefulWidget {
  const CreateClientDialog({
    super.key,
    required this.sources,
    required this.endpoint,
  });
  final List<String> sources;
  final String endpoint;
  @override
  State<CreateClientDialog> createState() => _CreateClientDialogState();
}

class _CreateClientDialogState extends State<CreateClientDialog> {
  final form = GlobalKey<FormState>();
  final name = TextEditingController();
  final dns = TextEditingController(text: '1.1.1.1');
  late String source = widget.sources.first;
  bool get external => source.startsWith('amnezia-');
  @override
  void dispose() {
    name.dispose();
    dns.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('Create VPN client'),
    content: SizedBox(
      width: 480,
      child: SingleChildScrollView(
        child: Form(
          key: form,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Server ${widget.endpoint}'),
              const SizedBox(height: 16),
              DropdownButtonFormField<String>(
                isExpanded: true,
                initialValue: source,
                decoration: const InputDecoration(
                  labelText: 'VPN protocol / installation',
                ),
                items: [
                  for (final item in widget.sources)
                    DropdownMenuItem(
                      value: item,
                      child: Text(
                        vpnSourceLabel(item),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                ],
                onChanged: (value) {
                  if (value != null) setState(() => source = value);
                },
              ),
              const SizedBox(height: 16),
              TextFormField(
                controller: name,
                autofocus: true,
                decoration: InputDecoration(
                  labelText: 'Client name',
                  helperText: external || source == VlessConnection.source
                      ? 'Up to 64 characters.'
                      : 'Up to 15 letters, numbers, underscores or hyphens.',
                ),
                validator: (value) {
                  final text = value?.trim() ?? '';
                  final valid = external || source == VlessConnection.source
                      ? text.isNotEmpty &&
                            text.runes.length <= 64 &&
                            !RegExp(r'[\x00-\x1f\x7f]').hasMatch(text)
                      : RegExp(r'^[A-Za-z0-9_-]{1,15}$').hasMatch(text);
                  return valid ? null : 'Enter a valid client name.';
                },
              ),
              if (external) ...[
                const SizedBox(height: 16),
                TextFormField(
                  controller: dns,
                  decoration: const InputDecoration(
                    labelText: 'Client DNS address',
                  ),
                  validator: (value) =>
                      InternetAddress.tryParse(value?.trim() ?? '') == null
                      ? 'Enter a DNS IP address.'
                      : null,
                ),
              ],
              const SizedBox(height: 16),
              Text(
                source == VlessConnection.source
                    ? 'A separate UUID and Short ID will be created for this device. Applying client changes briefly restarts only VLESS; AmneziaWG stays running.'
                    : 'A separate key will be created for this device. Existing clients will stay connected.',
              ),
            ],
          ),
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('Cancel'),
      ),
      FilledButton(
        onPressed: () {
          if (form.currentState!.validate()) {
            Navigator.pop(
              context,
              ClientDraft(name.text.trim(), source, dns.text.trim()),
            );
          }
        },
        child: const Text('Create'),
      ),
    ],
  );
}
