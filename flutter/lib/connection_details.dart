class ConnectionDetails {
  const ConnectionDetails({
    required this.host,
    required this.port,
    required this.user,
    required this.password,
  });

  final String host;
  final int port;
  final String user;
  final String password;

  String format({bool revealPassword = false}) =>
      'IP: $host\nPort: $port\nUser: $user\nPassword: ${revealPassword ? password : '********'}';
}
