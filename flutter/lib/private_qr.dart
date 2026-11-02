import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// Validates before building the package widget, including oversized payloads.
class PrivateQr extends StatelessWidget {
  const PrivateQr({
    super.key,
    required this.data,
    required this.label,
    required this.fallback,
  });
  final String data, label, fallback;

  @override
  Widget build(BuildContext context) {
    try {
      final result = QrValidator.validate(
        data: data,
        version: QrVersions.auto,
        errorCorrectionLevel: QrErrorCorrectLevel.L,
      );
      if (result.isValid && result.qrCode != null) {
        // The public painter constructor forces full encoding; the validator
        // alone can defer an oversized-payload error until a later layout.
        QrPainter.withQr(qr: result.qrCode!);
        return QrImageView.withQr(
          qr: result.qrCode!,
          backgroundColor: Colors.white,
          semanticsLabel: label,
          errorStateBuilder: (_, _) => Center(child: Text(fallback)),
        );
      }
    } catch (_) {
      // qr_flutter can throw before its own errorStateBuilder for long data.
    }
    return Center(
      child: Padding(padding: const EdgeInsets.all(16), child: Text(fallback)),
    );
  }
}
