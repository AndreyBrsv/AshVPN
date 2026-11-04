import 'server_template.dart';

/// Session-only answers. Serialization is exclusively for the OS credential vault.
class SetupSecrets {
  const SetupSecrets({
    this.connectionUser = 'root',
    this.connectionPassword = '',
    this.rootPassword = '',
    this.adminName = '',
    this.adminPassword = '',
    this.socksUser = '',
    this.socksPassword = '',
    this.sshPublicKey = '',
    this.sshPrivateKey = '',
    this.sshKeyPassphrase = '',
  });
  final String connectionUser, connectionPassword, rootPassword;
  final String adminName, adminPassword, socksUser, socksPassword, sshPublicKey;
  final String sshPrivateKey, sshKeyPassphrase;

  Map<String, String> toVault() => {
    'connection_user': connectionUser,
    'connection_password': connectionPassword,
    'root_password': rootPassword,
    'admin_name': adminName,
    'admin_password': adminPassword,
    'socks_user': socksUser,
    'socks_password': socksPassword,
    'ssh_public_key': sshPublicKey,
    'ssh_private_key': sshPrivateKey,
    'ssh_key_passphrase': sshKeyPassphrase,
  };
  factory SetupSecrets.fromVault(Map<String, dynamic> json) {
    if (json.values.any((value) => value is! String)) {
      throw const FormatException('Invalid protected template answers.');
    }
    return SetupSecrets(
      connectionUser: json['connection_user'] as String? ?? 'root',
      connectionPassword: json['connection_password'] as String? ?? '',
      rootPassword: json['root_password'] as String? ?? '',
      adminName: json['admin_name'] as String? ?? '',
      adminPassword: json['admin_password'] as String? ?? '',
      socksUser: json['socks_user'] as String? ?? '',
      socksPassword: json['socks_password'] as String? ?? '',
      sshPublicKey: json['ssh_public_key'] as String? ?? '',
      sshPrivateKey: json['ssh_private_key'] as String? ?? '',
      sshKeyPassphrase: json['ssh_key_passphrase'] as String? ?? '',
    );
  }

  String? validate(ServerTemplate answers, {String? activeUser}) {
    if (answers.disablePasswordLogin &&
        !answers.generateSshKey &&
        sshPrivateKey.isEmpty) {
      return 'Generate or import an SSH private key before disabling password login.';
    }
    if (answers.installVless &&
        (answers.vlessPort == answers.sshPort ||
            (answers.installSocks && answers.vlessPort == answers.socksPort))) {
      return 'VLESS, SSH and SOCKS5 need different TCP ports. AmneziaWG uses UDP and may use the same number.';
    }
    if (!answers.installVless && answers.vlessClientNames.isNotEmpty) {
      return 'Select VLESS + Reality to create VLESS clients during setup.';
    }
    if (answers.installSocks && answers.socksPort == answers.sshPort) {
      return 'SOCKS5 and SSH need different TCP ports.';
    }
    if (answers.changeRootPassword && !passwordValid(rootPassword)) {
      return 'The new root password needs at least 8 characters and no line breaks.';
    }
    if (answers.createAdmin &&
        (!usernameValid(adminName) || !passwordValid(adminPassword))) {
      return 'Enter an administrator name and a password with at least 8 characters.';
    }
    if (answers.disableRoot && !answers.createAdmin && activeUser == 'root') {
      return 'Create an administrator before disabling root SSH login.';
    }
    if (answers.installSocks &&
        (!RegExp(r'^[A-Za-z0-9_]{1,128}$').hasMatch(socksUser) ||
            !RegExp(r'^[A-Za-z0-9_]{8,128}$').hasMatch(socksPassword))) {
      return 'SOCKS5 needs a username and an 8–128 character password using letters, numbers or underscores.';
    }
    if (!answers.installAwg && answers.clientNames.isNotEmpty) {
      return 'Select AmneziaWG to create VPN clients during setup.';
    }
    if (sshPublicKey.isNotEmpty &&
        (sshPublicKey.contains(RegExp(r'[\r\n\x00]')) ||
            !RegExp(
              r'^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+=*( .*)?$',
            ).hasMatch(sshPublicKey))) {
      return 'Paste one complete OpenSSH public key, or leave it empty.';
    }
    return null;
  }

  static bool usernameValid(String value) =>
      RegExp(r'^[a-z_][a-z0-9_-]{0,30}$').hasMatch(value) &&
      value != 'root' &&
      value != 'nobody';
  static bool passwordValid(String value) =>
      value.length >= 8 &&
      value.length <= 1024 &&
      !value.contains(RegExp(r'[\r\n\x00]'));
}
