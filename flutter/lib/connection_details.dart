class ConnectionDetails {
  const ConnectionDetails({
    required this.host,
    required this.port,
    required this.user,
    required this.password,
    this.privateKey = '',
    this.keyPassphrase = '',
  });

  final String host;
  final int port;
  final String user;
  final String password;
  final String privateKey, keyPassphrase;
  bool get usesKey => privateKey.isNotEmpty;

  String format({bool revealPassword = false}) =>
      'IP: $host\nPort: $port\nUser: $user\n${usesKey ? 'Authentication: SSH key' : 'Password: ${revealPassword ? password : '********'}'}';
}
