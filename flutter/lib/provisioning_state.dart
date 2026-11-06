import 'dart:convert';

import 'server_template.dart';
import 'setup_secrets.dart';

/// A server stores intentions and step names, never credentials or device names.
Map<String, Object> serverSetupIntent(ServerTemplate answers) => {
  for (final entry in answers.toJson().entries)
    if (!{
      'name',
      'credentials_ref',
      'client_names',
      'vless_client_names',
    }.contains(entry.key))
      entry.key: entry.value,
  'awg_client_count': answers.clientNames.length,
  'vless_client_count': answers.vlessClientNames.length,
};

/// Protected local recovery answers, associated with one server-side run.
class ProvisioningDraft {
  const ProvisioningDraft({
    required this.runId,
    required this.answers,
    required this.secrets,
  });

  final String runId;
  final ServerTemplate answers;
  final SetupSecrets secrets;

  Map<String, Object> toVault() => {
    'run_id': runId,
    'answers': answers.toJson(),
    'secrets': secrets.toVault(),
  };

  factory ProvisioningDraft.fromVault(Object? value) {
    if (value is! Map ||
        value['run_id'] is! String ||
        (value['run_id'] as String).isEmpty ||
        value['secrets'] is! Map<String, dynamic>) {
      throw const FormatException('Invalid protected setup recovery answers.');
    }
    return ProvisioningDraft(
      runId: value['run_id'] as String,
      answers: ServerTemplate.fromJson(value['answers']),
      secrets: SetupSecrets.fromVault(value['secrets'] as Map<String, dynamic>),
    );
  }

  bool matches(ServerTemplate other, SetupSecrets protected) =>
      jsonEncode(answers.toJson()) == jsonEncode(other.toJson()) &&
      jsonEncode(secrets.forTemplate().toVault()) ==
          jsonEncode(protected.forTemplate().toVault());
}
