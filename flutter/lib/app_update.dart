import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as path;

import 'json_file_store.dart';

const updateRepository = 'AndreyBrsv/Ashapp';
const updateReleasePage =
    'https://github.com/$updateRepository/releases/latest';
const _downloadPrefix =
    'https://github.com/$updateRepository/releases/download/';
const _maximumInstallerSize = 1024 * 1024 * 1024;

class UpdateException implements Exception {
  const UpdateException(this.message);
  final String message;
  @override
  String toString() => message;
}

class AppVersion implements Comparable<AppVersion> {
  const AppVersion(this.major, this.minor, this.patch);
  final int major, minor, patch;

  factory AppVersion.parse(String value) {
    final match = RegExp(
      r'^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})(?:\+\d+)?$',
    ).firstMatch(value);
    if (match == null) {
      throw const UpdateException('Unsupported release version.');
    }
    return AppVersion(
      int.parse(match[1]!),
      int.parse(match[2]!),
      int.parse(match[3]!),
    );
  }

  @override
  int compareTo(AppVersion other) {
    for (final pair in [
      (major, other.major),
      (minor, other.minor),
      (patch, other.patch),
    ]) {
      final order = pair.$1.compareTo(pair.$2);
      if (order != 0) return order;
    }
    return 0;
  }

  @override
  String toString() => '$major.$minor.$patch';
}

class UpdatePlatform {
  const UpdatePlatform({required this.version, required this.target});
  final AppVersion version;
  final String target;
  static const targets = ['windows-x64', 'macos-x64', 'macos-arm64'];
  String get extension => target == 'windows-x64' ? '.exe' : '.pkg';

  factory UpdatePlatform.fromJson(Map<Object?, Object?> data) {
    if (data['version'] is! String || !targets.contains(data['target'])) {
      throw const UpdateException(
        'Updates are supported on Windows x64 and macOS Intel/Apple Silicon.',
      );
    }
    return UpdatePlatform(
      version: AppVersion.parse(data['version'] as String),
      target: data['target'] as String,
    );
  }
}

class UpdateAsset {
  const UpdateAsset({
    required this.name,
    required this.url,
    required this.size,
    required this.sha256,
  });
  final String name, sha256;
  final Uri url;
  final int size;

  factory UpdateAsset.fromJson(
    Map<String, dynamic> raw,
    String tag,
    String name,
    int limit,
  ) {
    final digest = raw['digest'];
    final expected = '$_downloadPrefix$tag/$name';
    if (raw['name'] != name ||
        raw['state'] != 'uploaded' ||
        raw['browser_download_url'] != expected ||
        raw['size'] is! int ||
        (raw['size'] as int) <= 0 ||
        (raw['size'] as int) > limit ||
        digest is! String ||
        !RegExp(r'^sha256:[a-f0-9]{64}$').hasMatch(digest)) {
      throw const UpdateException(
        'This release has incomplete or unverified update files.',
      );
    }
    return UpdateAsset(
      name: name,
      url: Uri.parse(expected),
      size: raw['size'] as int,
      sha256: digest.substring(7),
    );
  }
}

class AppRelease {
  const AppRelease({
    required this.version,
    required this.notes,
    required this.installer,
    required this.manifest,
    required this.checksums,
  });
  final AppVersion version;
  final String notes;
  final UpdateAsset installer, manifest, checksums;

  static AppRelease? newer(Object? raw, UpdatePlatform platform) {
    if (raw is! Map<String, dynamic> ||
        raw['draft'] != false ||
        raw['prerelease'] != false ||
        raw['tag_name'] is! String) {
      throw const UpdateException('Invalid stable-release response.');
    }
    final tag = raw['tag_name'] as String;
    if (!RegExp(r'^v\d+\.\d+\.\d+$').hasMatch(tag)) {
      throw const UpdateException('Unsupported release tag.');
    }
    final version = AppVersion.parse(tag.substring(1));
    if (version.compareTo(platform.version) <= 0) return null;
    final list = raw['assets'];
    if (list is! List || list.length > 100) {
      throw const UpdateException('Invalid release assets.');
    }
    final assets = <String, Map<String, dynamic>>{};
    for (final item in list) {
      if (item is! Map<String, dynamic> ||
          item['name'] is! String ||
          assets.containsKey(item['name'])) {
        throw const UpdateException('Ambiguous release assets.');
      }
      assets[item['name'] as String] = item;
    }
    UpdateAsset asset(String name, int limit) =>
        UpdateAsset.fromJson(assets[name] ?? {}, tag, name, limit);
    // A partially uploaded release must never become an update for one OS only.
    for (final target in UpdatePlatform.targets) {
      final suffix = target == 'windows-x64' ? '.exe' : '.pkg';
      asset('Ashapp-$tag-$target-setup$suffix', _maximumInstallerSize);
      asset('Ashapp-$tag-$target.build.json', 128 * 1024);
    }
    final stem = 'Ashapp-$tag-${platform.target}';
    return AppRelease(
      version: version,
      notes: raw['body'] is String
          ? (raw['body'] as String).substring(
              0,
              (raw['body'] as String).length.clamp(0, 16000),
            )
          : '',
      installer: asset(
        '$stem-setup${platform.extension}',
        _maximumInstallerSize,
      ),
      manifest: asset('$stem.build.json', 128 * 1024),
      checksums: asset('SHA256SUMS', 128 * 1024),
    );
  }
}

class UpdateCancellation {
  bool cancelled = false;
  void Function()? abort;
  void cancel() {
    cancelled = true;
    abort?.call();
  }

  void check() {
    if (cancelled) throw const UpdateException('Download cancelled.');
  }
}

abstract class UpdateTransport {
  Future<Stream<List<int>>> get(Uri url, UpdateCancellation cancellation);
}

/// Public, unauthenticated GitHub requests only. No SSH data enters this service.
class GitHubUpdateTransport implements UpdateTransport {
  static bool allowed(Uri url) =>
      url.scheme == 'https' &&
      url.port == 443 &&
      url.userInfo.isEmpty &&
      url.fragment.isEmpty &&
      const [
        'api.github.com',
        'github.com',
        'release-assets.githubusercontent.com',
        'objects.githubusercontent.com',
      ].contains(url.host);

  @override
  Future<Stream<List<int>>> get(
    Uri url,
    UpdateCancellation cancellation,
  ) async {
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 20);
    cancellation.abort = () => client.close(force: true);
    try {
      for (var redirects = 0; redirects < 6; redirects++) {
        cancellation.check();
        if (!allowed(url)) {
          throw const UpdateException('An update URL was refused.');
        }
        final request = await client
            .getUrl(url)
            .timeout(const Duration(seconds: 30));
        request.followRedirects = false;
        request.headers.set(HttpHeaders.userAgentHeader, 'Ashapp-update-check');
        request.headers.set(
          HttpHeaders.acceptHeader,
          url.host == 'api.github.com'
              ? 'application/vnd.github+json'
              : 'application/octet-stream',
        );
        final response = await request.close().timeout(
          const Duration(seconds: 30),
        );
        if ([301, 302, 303, 307, 308].contains(response.statusCode)) {
          final location = response.headers.value(HttpHeaders.locationHeader);
          if (location == null) {
            throw const UpdateException('Invalid download redirect.');
          }
          // Do not drain arbitrary redirect bodies; a fresh connection follows.
          final subscription = response.listen((_) {});
          await subscription.cancel();
          url = url.resolve(location);
          continue;
        }
        if (response.statusCode != 200) {
          if (response.statusCode == 403 || response.statusCode == 429) {
            throw const UpdateException(
              'GitHub temporarily limited update checks. Try again later.',
            );
          }
          throw const UpdateException(
            'Could not retrieve this release. Try again later.',
          );
        }
        return _body(response, client, cancellation);
      }
      throw const UpdateException('Too many download redirects.');
    } catch (_) {
      client.close(force: true);
      cancellation.abort = null;
      rethrow;
    }
  }

  Stream<List<int>> _body(
    HttpClientResponse response,
    HttpClient client,
    UpdateCancellation cancellation,
  ) async* {
    try {
      await for (final chunk in response.timeout(const Duration(seconds: 30))) {
        cancellation.check();
        yield chunk;
      }
    } finally {
      cancellation.abort = null;
      client.close(force: true);
    }
  }
}

class _DigestSink implements Sink<Digest> {
  Digest? value;
  @override
  void add(Digest value) => this.value = value;
  @override
  void close() {}
}

class PreparedUpdate {
  const PreparedUpdate(this.release, this.file, this.directory);
  final AppRelease release;
  final File file;
  final Directory directory;
}

class UpdateRepository {
  UpdateRepository({required this.transport, required this.cache});
  final UpdateTransport transport;
  final Directory cache;

  Future<List<int>> _read(Uri uri, int limit, UpdateCancellation token) async {
    final result = <int>[];
    await for (final chunk in await transport.get(uri, token)) {
      token.check();
      if (result.length + chunk.length > limit) {
        throw const UpdateException('Update metadata is too large.');
      }
      result.addAll(chunk);
    }
    return result;
  }

  Future<AppRelease?> check(UpdatePlatform platform) async {
    final token = UpdateCancellation();
    try {
      final bytes = await _read(
        Uri.https('api.github.com', '/repos/$updateRepository/releases/latest'),
        1024 * 1024,
        token,
      ).timeout(const Duration(seconds: 60));
      return AppRelease.newer(jsonDecode(utf8.decode(bytes)), platform);
    } finally {
      token.cancel();
    }
  }

  Future<List<int>> _verifiedMetadata(
    UpdateAsset asset,
    UpdateCancellation token,
  ) async {
    final bytes = await _read(asset.url, 128 * 1024, token);
    if (bytes.length != asset.size ||
        sha256.convert(bytes).toString() != asset.sha256) {
      throw const UpdateException('Update metadata checksum mismatch.');
    }
    return bytes;
  }

  Future<PreparedUpdate> download(
    AppRelease release,
    UpdatePlatform platform,
    UpdateCancellation token,
    void Function(double) progress,
  ) async {
    Directory? staging;
    try {
      final sums = utf8.decode(
        await _verifiedMetadata(release.checksums, token),
      );
      final entries = <String, String>{};
      for (final line in const LineSplitter().convert(sums)) {
        final match = RegExp(r'^([a-f0-9]{64})  ([A-Za-z0-9_.-]+)$')
            .firstMatch(line);
        if (match == null || entries.containsKey(match[2])) {
          throw const UpdateException('Invalid release checksum file.');
        }
        entries[match[2]!] = match[1]!;
      }
      if (entries[release.installer.name] != release.installer.sha256 ||
          entries[release.manifest.name] != release.manifest.sha256) {
        throw const UpdateException('Release checksum files disagree.');
      }
      final manifest = jsonDecode(
        utf8.decode(await _verifiedMetadata(release.manifest, token)),
      );
      if (manifest is! Map ||
          manifest['version'] != release.version.toString() ||
          manifest['target'] != platform.target ||
          manifest['source_commit'] is! String ||
          !RegExp(r'^[a-f0-9]{40}$')
              .hasMatch(manifest['source_commit'] as String) ||
          manifest['installer'] != release.installer.name ||
          manifest['installer_sha256'] != release.installer.sha256 ||
          manifest['installer_size'] != release.installer.size) {
        throw const UpdateException('Installer source identity mismatch.');
      }
      token.check();
      await cache.create(recursive: true);
      if (await FileSystemEntity.type(cache.path, followLinks: false) !=
          FileSystemEntityType.directory) {
        throw const UpdateException('Invalid update cache.');
      }
      staging = await cache.createTemp('download-');
      final file = File(path.join(staging.path, release.installer.name));
      final output = await file.open(mode: FileMode.writeOnly);
      final digest = _DigestSink();
      final hash = sha256.startChunkedConversion(digest);
      var received = 0;
      try {
        await for (final chunk in await transport.get(
          release.installer.url,
          token,
        )) {
          token.check();
          received += chunk.length;
          if (received > release.installer.size) {
            throw const UpdateException('Installer length mismatch.');
          }
          hash.add(chunk);
          await output.writeFrom(chunk);
          progress(received / release.installer.size);
        }
        await output.flush();
      } finally {
        hash.close();
        await output.close();
      }
      token.check();
      if (received != release.installer.size ||
          digest.value.toString() != release.installer.sha256) {
        throw const UpdateException(
          'Installer checksum mismatch. The download was discarded.',
        );
      }
      return PreparedUpdate(release, file, staging);
    } catch (_) {
      if (staging != null) await staging.delete(recursive: true);
      rethrow;
    }
  }

  Future<void> verify(PreparedUpdate update) async {
    if (!path.isWithin(cache.absolute.path, update.file.absolute.path) ||
        await FileSystemEntity.type(update.file.path, followLinks: false) !=
            FileSystemEntityType.file ||
        await update.file.length() != update.release.installer.size ||
        (await sha256.bind(update.file.openRead()).first).toString() !=
            update.release.installer.sha256) {
      throw const UpdateException(
        'The prepared installer changed. Download it again.',
      );
    }
  }

  Future<void> discard(PreparedUpdate update) async {
    final directory = update.directory.absolute;
    if (!path.isWithin(cache.absolute.path, directory.path) ||
        !path.basename(directory.path).startsWith('download-') ||
        await FileSystemEntity.type(directory.path, followLinks: false) !=
            FileSystemEntityType.directory) {
      throw const UpdateException(
        'The update cache could not be removed safely.',
      );
    }
    final resolvedCache = await cache.resolveSymbolicLinks();
    final resolvedDirectory = await directory.resolveSymbolicLinks();
    if (!path.isWithin(resolvedCache, resolvedDirectory)) {
      throw const UpdateException(
        'The update cache could not be removed safely.',
      );
    }
    await directory.delete(recursive: true);
  }
}

abstract class UpdateRuntime {
  Future<UpdatePlatform> platform();
  Future<void> openInstaller(File file, {required String expectedSha256});
  Future<void> quit();
}

class NativeUpdateRuntime implements UpdateRuntime {
  static const channel = MethodChannel('ashapp/app-update');
  @override
  Future<UpdatePlatform> platform() async => UpdatePlatform.fromJson(
    await channel.invokeMapMethod<Object?, Object?>('info') ?? {},
  );
  @override
  Future<void> openInstaller(
    File file, {
    required String expectedSha256,
  }) async {
    await channel.invokeMethod<void>('openInstaller', {
      'path': file.absolute.path,
      'sha256': expectedSha256,
    });
  }

  @override
  Future<void> quit() => channel.invokeMethod<void>('quit');
}

enum UpdatePhase {
  idle,
  checking,
  available,
  downloading,
  ready,
  installing,
  handedOff,
}

class AppUpdateController extends ChangeNotifier {
  AppUpdateController({
    required this.repository,
    required this.runtime,
    required this.preferences,
    DateTime Function()? now,
  }) : _now = now ?? DateTime.now;
  final UpdateRepository repository;
  final UpdateRuntime runtime;
  final JsonFileStore preferences;
  final DateTime Function() _now;
  UpdatePlatform? platform;
  AppRelease? release;
  PreparedUpdate? prepared;
  UpdatePhase phase = UpdatePhase.idle;
  bool automatic = true, _disposed = false, _started = false;
  DateTime? lastChecked;
  String error = '', notice = '';
  double progress = 0;
  UpdateCancellation? _download;
  Timer? _timer;
  bool get working => [
    UpdatePhase.checking,
    UpdatePhase.downloading,
    UpdatePhase.installing,
    UpdatePhase.handedOff,
  ].contains(phase);
  bool get locksWorkspace =>
      phase == UpdatePhase.installing || phase == UpdatePhase.handedOff;
  void _changed() {
    if (!_disposed) notifyListeners();
  }

  Future<void> start() async {
    if (_started) return;
    _started = true;
    try {
      final data = await preferences.read();
      if (data != null) {
        if (data is! Map ||
            data['version'] != 1 ||
            data['automatic'] is! bool ||
            (data['last_checked'] != null && data['last_checked'] is! String)) {
          throw const FormatException();
        }
        automatic = data['automatic'] as bool;
        lastChecked = data['last_checked'] == null
            ? null
            : DateTime.parse(data['last_checked'] as String);
      }
      platform = await runtime.platform();
    } catch (_) {
      automatic = false;
      error = 'Update settings or platform information could not be read. You can retry a manual check.';
    }
    if (_disposed) return;
    _changed();
    _timer = Timer.periodic(const Duration(hours: 1), (_) => _automaticCheck());
    await _automaticCheck();
  }

  Future<void> _automaticCheck() async {
    if (!automatic || _disposed || working || release != null) return;
    if (lastChecked == null ||
        _now().difference(lastChecked!) >= const Duration(hours: 24)) {
      await check();
    }
  }

  Future<void> _save() => preferences.write({
    'version': 1,
    'automatic': automatic,
    'last_checked': lastChecked?.toUtc().toIso8601String(),
  });

  Future<void> setAutomatic(bool value) async {
    final previous = automatic;
    automatic = value;
    try {
      await _save();
    } catch (_) {
      automatic = previous;
      error = 'Could not save the update preference.';
    }
    _changed();
  }

  Future<void> check() async {
    if (working || prepared != null || _disposed) return;
    phase = UpdatePhase.checking;
    error = '';
    notice = '';
    _changed();
    try {
      platform ??= await runtime.platform();
      release = await repository.check(platform!);
      lastChecked = _now();
      await _save();
      notice = release == null
          ? 'No newer stable release is available.'
          : 'A new version is available.';
    } catch (e) {
      error = _message(
        e,
        'Could not check for updates. Check your connection and try again.',
      );
    } finally {
      phase = release == null ? UpdatePhase.idle : UpdatePhase.available;
      _changed();
    }
  }

  String _message(Object e, String fallback) {
    if (e is UpdateException) return e.message;
    // This channel returns fixed app-owned messages, never OS paths or payloads.
    if (e is PlatformException &&
        e.code == 'update_failed' &&
        e.message != null) {
      return e.message!;
    }
    return fallback;
  }

  Future<void> download() async {
    if (working ||
        release == null ||
        platform == null ||
        prepared != null ||
        _disposed) {
      return;
    }
    phase = UpdatePhase.downloading;
    error = '';
    notice = '';
    progress = 0;
    final token = _download = UpdateCancellation();
    _changed();
    try {
      prepared = await repository
          .download(release!, platform!, token, (value) {
            progress = value;
            _changed();
          })
          .timeout(
            const Duration(minutes: 15),
            onTimeout: () {
              token.cancel();
              throw const UpdateException('Download timed out. Try again.');
            },
          );
      if (_disposed) {
        await prepared!.directory.delete(recursive: true);
        prepared = null;
        return;
      }
      notice = 'Download verified. Ready to install.';
    } catch (e) {
      error = e is UpdateException
          ? e.message
          : token.cancelled
          ? 'Download cancelled. You can try again.'
          : 'Download failed. Try again.';
    } finally {
      _download = null;
      phase = prepared == null ? UpdatePhase.available : UpdatePhase.ready;
      _changed();
    }
  }

  void cancelDownload() => _download?.cancel();

  Future<void> discardDownload() async {
    if (working || prepared == null || _disposed) return;
    try {
      await repository.discard(prepared!);
      prepared = null;
      phase = UpdatePhase.available;
      notice = 'Download removed. You can download it again.';
      error = '';
    } catch (_) {
      error = 'Could not remove the prepared download. Restart the app to download again.';
    }
    _changed();
  }

  Future<bool> install({required bool Function() canInstall}) async {
    if (working || prepared == null || _disposed) return false;
    if (!canInstall()) {
      error = 'Finish all server tasks and close setup/connection dialogs before installing.';
      _changed();
      return false;
    }
    phase = UpdatePhase.installing;
    error = '';
    _changed();
    var opened = false;
    try {
      await repository.verify(prepared!);
      if (!canInstall()) {
        throw const UpdateException(
          'A server task started. Finish it before installing.',
        );
      }
      await runtime.openInstaller(
        prepared!.file,
        expectedSha256: prepared!.release.installer.sha256,
      );
      opened = true;
      phase = UpdatePhase.handedOff;
      notice = 'Ashapp will restart after the update. Approve any system security prompt.';
      _changed();
      await runtime.quit();
      return true;
    } catch (e) {
      // A successful handoff must not launch a second installer if quitting fails.
      phase = opened ? UpdatePhase.handedOff : UpdatePhase.ready;
      error = _message(
        e,
        opened
            ? 'The update is ready to run. Close Ashapp to continue.'
            : 'Could not start the update. Your current app is unchanged.',
      );
      _changed();
      return false;
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _timer?.cancel();
    _download?.cancel();
    super.dispose();
  }
}
