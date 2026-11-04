import 'dart:convert';

import 'package:dartssh2/dartssh2.dart';
import 'package:pinenacl/ed25519.dart' as ed25519;

/// Private material is held in memory or the OS vault, never profile JSON.
class SshIdentity {
  const SshIdentity(this.privateKey, this.publicKey);
  final String privateKey, publicKey;

  static SshIdentity generate() {
    final signing = ed25519.SigningKey.generate();
    final key = OpenSSHEd25519KeyPair(
      signing.verifyKey.asTypedList,
      signing.asTypedList,
      'Ashapp',
    );
    return SshIdentity(key.toPem(), _public(key));
  }

  static SshIdentity parse(String pem, String passphrase) {
    if (pem.length > 32768) {
      throw const FormatException('SSH private key is too large.');
    }
    try {
      final keys = SSHKeyPair.fromPem(
        pem,
        passphrase.isEmpty ? null : passphrase,
      );
      if (keys.length != 1) throw const FormatException();
      return SshIdentity(pem, _public(keys.single));
    } catch (_) {
      throw const FormatException(
        'Could not unlock one supported SSH private key.',
      );
    }
  }

  static String _public(SSHKeyPair key) =>
      '${key.name} ${base64.encode(key.toPublicKey().encode())} Ashapp';
}
