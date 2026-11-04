import 'vless_connection.dart';

/// A reusable set of non-secret server provisioning choices.
/// Credentials and generated VPN configurations must never be serialized here.
class ServerTemplate {
  factory ServerTemplate({
    required String name,
    required bool blockPing,
    required bool disableRoot,
    required bool installAwg,
    required bool installSocks,
    required int awgPort,
    required List<String> clientNames,
    bool upgradePackages = false,
    bool changeRootPassword = false,
    bool createAdmin = true,
    String awgDns = '1.1.1.1',
    int socksPort = 1080,
    int sshPort = 22,
    String? credentialsRef,
    bool installVless = false,
    int vlessPort = 443,
    String realitySni = 'www.microsoft.com',
    String realityFingerprint = 'chrome',
    List<String> vlessClientNames = const [],
    bool protectSsh = true,
    bool configureFirewall = true,
    bool automaticUpdates = false,
    bool disablePasswordLogin = false,
    bool generateSshKey = false,
    String socksAccess = 'public',
  }) => fromJson({
    'name': name,
    'block_ping': blockPing,
    'disable_root': disableRoot,
    'install_awg': installAwg,
    'install_socks': installSocks,
    'awg_port': awgPort,
    'client_names': clientNames,
    'upgrade_packages': upgradePackages,
    'change_root_password': changeRootPassword,
    'create_admin': createAdmin,
    'awg_dns': awgDns,
    'socks_port': socksPort,
    'ssh_port': sshPort,
    'credentials_ref': ?credentialsRef,
    'install_vless': installVless,
    'vless_port': vlessPort,
    'reality_sni': realitySni,
    'reality_fingerprint': realityFingerprint,
    'vless_client_names': vlessClientNames,
    'protect_ssh': protectSsh,
    'configure_firewall': configureFirewall,
    'automatic_updates': automaticUpdates,
    'disable_password_login': disablePasswordLogin,
    'generate_ssh_key': generateSshKey,
    'socks_access': socksAccess,
  });

  const ServerTemplate._({
    required this.name,
    required this.blockPing,
    required this.disableRoot,
    required this.installAwg,
    required this.installSocks,
    required this.awgPort,
    required this.clientNames,
    required this.upgradePackages,
    required this.changeRootPassword,
    required this.createAdmin,
    required this.awgDns,
    required this.socksPort,
    required this.sshPort,
    this.credentialsRef,
    required this.installVless,
    required this.vlessPort,
    required this.realitySni,
    required this.realityFingerprint,
    required this.vlessClientNames,
    required this.protectSsh,
    required this.configureFirewall,
    required this.automaticUpdates,
    required this.disablePasswordLogin,
    required this.generateSshKey,
    required this.socksAccess,
  });

  final String name;
  final bool blockPing;
  final bool disableRoot;
  final bool installAwg;
  final bool installSocks;
  final int awgPort;
  final List<String> clientNames;
  final bool upgradePackages;
  final bool changeRootPassword;
  final bool createAdmin;
  final String awgDns;
  final int socksPort;
  final int sshPort;
  final String? credentialsRef;
  final bool installVless;
  final int vlessPort;
  final String realitySni, realityFingerprint;
  final List<String> vlessClientNames;
  final bool protectSsh, configureFirewall, automaticUpdates;
  final bool disablePasswordLogin, generateSshKey;
  final String socksAccess;
  ServerTemplate withCredentialsRef(String ref) =>
      fromJson({...toJson(), 'credentials_ref': ref});

  Map<String, Object> toJson() => {
    'name': name,
    'block_ping': blockPing,
    'disable_root': disableRoot,
    'install_awg': installAwg,
    'install_socks': installSocks,
    'awg_port': awgPort,
    'client_names': List<String>.unmodifiable(clientNames),
    'upgrade_packages': upgradePackages,
    'change_root_password': changeRootPassword,
    'create_admin': createAdmin,
    'awg_dns': awgDns,
    'socks_port': socksPort,
    'ssh_port': sshPort,
    'credentials_ref': ?credentialsRef,
    'install_vless': installVless,
    'vless_port': vlessPort,
    'reality_sni': realitySni,
    'reality_fingerprint': realityFingerprint,
    'vless_client_names': List<String>.unmodifiable(vlessClientNames),
    'protect_ssh': protectSsh,
    'configure_firewall': configureFirewall,
    'automatic_updates': automaticUpdates,
    'disable_password_login': disablePasswordLogin,
    'generate_ssh_key': generateSshKey,
    'socks_access': socksAccess,
  };

  static ServerTemplate fromJson(Object? json) {
    if (json is! Map) {
      throw const FormatException('Invalid server template.');
    }
    final name = json['name'];
    final port = json['awg_port'];
    final clients = json['client_names'];
    final upgrade = json['upgrade_packages'] ?? false;
    final changeRoot = json['change_root_password'] ?? false;
    final createAdmin = json['create_admin'] ?? true;
    final dns = json['awg_dns'] ?? '1.1.1.1';
    final socksPort = json['socks_port'] ?? 1080;
    final sshPort = json['ssh_port'] ?? 22;
    final ref = json['credentials_ref'];
    final installVless = json['install_vless'] ?? false;
    final vlessPort = json['vless_port'] ?? 443;
    final sni = json['reality_sni'] ?? 'www.microsoft.com';
    final fingerprint = json['reality_fingerprint'] ?? 'chrome';
    final vlessClients = json['vless_client_names'] ?? <String>[];
    // Existing templates must not silently acquire new server mutations.
    final security = <String, bool>{};
    for (final key in [
      'protect_ssh',
      'configure_firewall',
      'automatic_updates',
      'disable_password_login',
      'generate_ssh_key',
    ]) {
      final value = json[key] ?? false;
      if (value is! bool) {
        throw const FormatException('Invalid security choices.');
      }
      security[key] = value;
    }
    final access = json['socks_access'] ?? 'public';
    if (access != 'public' && access != 'private') {
      throw const FormatException('Invalid SOCKS5 access mode.');
    }
    if (installVless is! bool ||
        vlessPort is! int ||
        vlessPort < 1 ||
        vlessPort > 65535 ||
        sni is! String ||
        !VlessConnection.validHostname(sni) ||
        fingerprint is! String ||
        !VlessConnection.fingerprints.contains(fingerprint) ||
        vlessClients is! List ||
        vlessClients.length > 200 ||
        vlessClients.any(
          (v) =>
              v is! String ||
              v.trim() != v ||
              v.isEmpty ||
              v.runes.length > 64 ||
              RegExp(r'[\x00-\x1f\x7f]').hasMatch(v),
        ) ||
        vlessClients.toSet().length != vlessClients.length) {
      throw const FormatException('Invalid VLESS template settings.');
    }
    if ((ref != null &&
            (ref is! String || !RegExp(r'^[a-f0-9]{32}$').hasMatch(ref))) ||
        name is! String ||
        name.trim().isEmpty ||
        name.length > 80 ||
        upgrade is! bool ||
        changeRoot is! bool ||
        createAdmin is! bool ||
        dns is! String ||
        !_ipv4(dns) ||
        socksPort is! int ||
        socksPort < 1 ||
        socksPort > 65535 ||
        sshPort is! int ||
        sshPort < 1 ||
        sshPort > 65535 ||
        port is! int ||
        port < 1 ||
        port > 65535 ||
        clients is! List ||
        clients.length > 200 ||
        clients.any(
          (value) =>
              value is! String ||
              !RegExp(r'^[A-Za-z0-9_-]{1,15}$').hasMatch(value),
        ) ||
        {
          'block_ping',
          'disable_root',
          'install_awg',
          'install_socks',
        }.any((key) => json[key] is! bool)) {
      throw const FormatException('Invalid server template.');
    }
    final names = clients.cast<String>();
    if (names.toSet().length != names.length) {
      throw const FormatException('Duplicate VPN client names.');
    }
    return ServerTemplate._(
      name: name.trim(),
      blockPing: json['block_ping'] as bool,
      disableRoot: json['disable_root'] as bool,
      installAwg: json['install_awg'] as bool,
      installSocks: json['install_socks'] as bool,
      awgPort: port,
      clientNames: List<String>.unmodifiable(names),
      upgradePackages: upgrade,
      changeRootPassword: changeRoot,
      createAdmin: createAdmin,
      awgDns: dns,
      socksPort: socksPort,
      sshPort: sshPort,
      credentialsRef: ref as String?,
      installVless: installVless,
      vlessPort: vlessPort,
      realitySni: sni,
      realityFingerprint: fingerprint,
      vlessClientNames: List<String>.unmodifiable(vlessClients.cast<String>()),
      protectSsh: security['protect_ssh']!,
      configureFirewall: security['configure_firewall']!,
      automaticUpdates: security['automatic_updates']!,
      disablePasswordLogin: security['disable_password_login']!,
      generateSshKey: security['generate_ssh_key']!,
      socksAccess: access as String,
    );
  }

  static bool _ipv4(String value) {
    final parts = value.split('.');
    return parts.length == 4 &&
        parts.every(
          (p) =>
              RegExp(r'^\d{1,3}$').hasMatch(p) &&
              int.parse(p) <= 255 &&
              int.parse(p).toString() == p,
        );
  }
}
