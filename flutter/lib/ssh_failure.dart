import 'dart:async';
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';

import 'host_key_store.dart';

String sshFailureMessage(Object error) {
  if (error is HostKeyChange) {
    return 'The SSH server key for ${error.endpoint} has changed. '
        'Review the new fingerprint before reconnecting. No password was sent.';
  }
  if (error is SSHAuthAbortError) {
    final reason = error.reason;
    return reason == null
        ? 'SSH connection ended before login completed. Check the server and network.'
        : sshFailureMessage(reason);
  }
  if (error is SSHSocketError) return sshFailureMessage(error.error);
  if (error is SSHAuthFailError) {
    return 'The server rejected SSH authentication. Check the current username, password or private key.';
  }
  if (error is SSHHostkeyError) {
    return 'SSH server key verification failed. Verify the server fingerprint before reconnecting.';
  }
  if (error is SSHHandshakeError) {
    return 'SSH handshake failed before login. Check server SSH compatibility and network access.';
  }
  if (error is SSHDisconnectError) {
    return 'The server closed the SSH connection (reason ${error.reasonCode}) before login completed.';
  }
  if (error is TimeoutException) {
    return 'SSH connection timed out. Check the server address, port and network.';
  }
  if (error is SocketException) {
    return 'Network error while opening SSH. Check the server address and port.';
  }
  if (error is StateError) return error.message.toString();
  return 'SSH connection failed (${error.runtimeType}). Check the server connection details.';
}
