import 'dart:io';

import 'json_file_store.dart';
import 'server_template.dart';

/// Stores only the allowlisted non-secret template fields.
class TemplateRepository {
  TemplateRepository(this.file);
  final File file;

  Future<List<ServerTemplate>> load() async {
    final root = await JsonFileStore(file).read();
    if (root == null) return [];
    if (root is! Map || root['version'] != 1 || root['templates'] is! List) {
      throw const FormatException('Invalid template file.');
    }
    final templates = (root['templates'] as List)
        .map(ServerTemplate.fromJson)
        .toList();
    _checkNames(templates);
    _pending(root);
    return templates;
  }

  Future<void> save(List<ServerTemplate> templates) async {
    final validated = templates
        .map((item) => ServerTemplate.fromJson(item.toJson()))
        .toList();
    _checkNames(validated);
    await JsonFileStore(file)
        .update((root) async => _document(validated, _pending(root)));
  }

  void _checkNames(List<ServerTemplate> templates) {
    if (templates.map((item) => item.name).toSet().length != templates.length) {
      throw const FormatException('Duplicate template names.');
    }
  }

  Future<String?> upsert(ServerTemplate template) async {
    String? replaced;
    await JsonFileStore(file).update((root) async {
      final templates = _decode(root);
      final previous = templates
          .where((t) => t.name == template.name)
          .firstOrNull;
      replaced = previous == null
          ? null
          : previous.credentialsRef ?? previous.name;
      return _document(
        [...templates.where((t) => t.name != template.name), template],
        [..._pending(root), if (replaced != null) replaced!],
      );
    });
    return replaced;
  }

  Future<String?> remove(String name) async {
    String? removed;
    await JsonFileStore(file).update((root) async {
      final templates = _decode(root);
      final previous = templates.where((t) => t.name == name).firstOrNull;
      removed = previous == null
          ? null
          : previous.credentialsRef ?? previous.name;
      return _document(templates.where((t) => t.name != name).toList(), [
        ..._pending(root),
        if (removed != null) removed!,
      ]);
    });
    return removed;
  }

  List<ServerTemplate> _decode(Object? root) {
    if (root == null) return [];
    if (root is! Map || root['version'] != 1 || root['templates'] is! List) {
      throw const FormatException('Invalid template file.');
    }
    final result = (root['templates'] as List)
        .map(ServerTemplate.fromJson)
        .toList();
    _checkNames(result);
    return result;
  }

  Map<String, Object> _document(
    List<ServerTemplate> templates,
    List<String> pending,
  ) => {
    'version': 1,
    'templates': templates.map((t) => t.toJson()).toList(),
    'pending_deletions': pending.toSet().toList(),
  };

  List<String> _pending(Object? root) {
    if (root == null) return [];
    if (root is! Map) throw const FormatException('Invalid template file.');
    final values = root['pending_deletions'] ?? [];
    if (values is! List ||
        values.length > 10000 ||
        values.any((v) => v is! String || v.isEmpty || v.length > 256)) {
      throw const FormatException('Invalid protected cleanup queue.');
    }
    return values.cast<String>();
  }

  Future<List<String>> pendingDeletions() async {
    final root = await JsonFileStore(file).read();
    final active = _decode(root).map((t) => t.credentialsRef ?? t.name).toSet();
    return _pending(root).where((ref) => !active.contains(ref)).toList();
  }

  Future<void> acknowledgeDeletion(String ref) => JsonFileStore(file).update(
    (root) async => _document(
      _decode(root),
      _pending(root).where((value) => value != ref).toList(),
    ),
  );
}
