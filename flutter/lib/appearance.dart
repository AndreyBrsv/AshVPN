import 'package:flutter/material.dart';

import 'json_file_store.dart';

abstract interface class AppearanceRepository {
  Future<ThemeMode> load();
  Future<void> save(ThemeMode mode);
}

class JsonAppearanceRepository implements AppearanceRepository {
  JsonAppearanceRepository(this.store);
  final JsonFileStore store;

  @override
  Future<ThemeMode> load() async {
    final data = await store.read();
    if (data == null) return ThemeMode.system;
    if (data is! Map || data['version'] != 1) {
      throw const FormatException('Invalid appearance settings.');
    }
    return switch (data['theme']) {
      'system' => ThemeMode.system,
      'light' => ThemeMode.light,
      'dark' => ThemeMode.dark,
      _ => throw const FormatException('Unknown appearance setting.'),
    };
  }

  @override
  Future<void> save(ThemeMode mode) =>
      store.write({'version': 1, 'theme': mode.name});
}

/// Application-wide appearance, independent of the selected server session.
class AppearanceController extends ChangeNotifier {
  AppearanceController({this.repository});
  final AppearanceRepository? repository;
  ThemeMode _mode = ThemeMode.system;
  ThemeMode get mode => _mode;
  bool _saving = false;
  bool get saving => _saving;
  String? _error;
  String? get error => _error;
  Future<void>? _initialization;
  bool _disposed = false;

  Future<void> initialize() => _initialization ??= _load();

  Future<void> _load() async {
    try {
      _mode = await repository?.load() ?? ThemeMode.system;
    } catch (_) {
      _mode = ThemeMode.system;
      _error =
          'Your appearance preference could not be loaded. '
          'Using System until you choose a theme.';
    }
    if (!_disposed) notifyListeners();
  }

  Future<void> select(ThemeMode mode) async {
    if (_saving || _disposed) return;
    _saving = true;
    notifyListeners();
    try {
      await initialize();
      await repository?.save(mode);
      _mode = mode;
      _error = null;
    } catch (_) {
      _error =
          'The theme could not be saved. Your previous choice is still '
          'active. Check local storage and try again.';
    } finally {
      _saving = false;
      if (!_disposed) notifyListeners();
    }
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}

class AppearanceScope extends InheritedNotifier<AppearanceController> {
  const AppearanceScope({
    super.key,
    required AppearanceController controller,
    required super.child,
  }) : super(notifier: controller);

  static AppearanceController? maybeOf(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<AppearanceScope>()?.notifier;
}
