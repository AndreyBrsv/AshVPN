import 'package:flutter/foundation.dart';

import 'connection_details.dart';
import 'server_profiles.dart';
import 'workspace_controller.dart';

/// Owns independent SSH sessions; selecting one never changes another's work.
class ServerWorkspace extends ChangeNotifier {
  ServerWorkspace(this.current) {
    _register(current);
  }
  WorkspaceController current;
  final _sessions = <WorkspaceController>[];
  final _attempts = <WorkspaceController, ServerProfile>{};
  final _listeners = <WorkspaceController, VoidCallback>{};
  List<WorkspaceController> get sessions => List.unmodifiable(_sessions);
  WorkspaceController? find(ServerProfile profile) {
    WorkspaceController? inactive;
    for (final session in _sessions) {
      if (session.ssh?.host == profile.ip &&
          session.ssh?.port == profile.sshPort) {
        if (session.connected || session.busy) return session;
        inactive = session;
      }
    }
    return inactive;
  }

  void _register(WorkspaceController session) {
    _sessions.add(session);
    session.beforeConnect = (details) => _reserve(session, details);
    void changed() {
      if (!session.busy) _attempts.remove(session);
      notifyListeners();
    }

    _listeners[session] = changed;
    session.addListener(changed);
  }

  void _reserve(WorkspaceController owner, ConnectionDetails details) {
    bool matches(String? host, int? port) =>
        host == details.host && port == details.port;
    for (final other in _sessions) {
      if (identical(owner, other)) continue;
      final pending = _attempts[other];
      if ((other.connected && matches(other.ssh?.host, other.ssh?.port)) ||
          (other.busy &&
              pending != null &&
              matches(pending.ip, pending.sshPort))) {
        throw StateError(
          'This server already has a session. Select it in the server menu.',
        );
      }
    }
    // Reservations contain no usernames or passwords.
    _attempts[owner] = ServerProfile(ip: details.host, sshPort: details.port);
  }

  WorkspaceController create() {
    final next = WorkspaceController(
      profilesRepository: current.profilesRepository,
      templatesRepository: current.templatesRepository,
      vault: current.vault,
      connector: current.connector,
      backendFactory: current.backendFactory,
    );
    _register(next);
    return next;
  }

  void select(WorkspaceController session) {
    if (!_sessions.contains(session)) throw ArgumentError('Unknown server.');
    current = session;
    notifyListeners();
  }

  @override
  void dispose() {
    for (final session in _sessions) {
      session.removeListener(_listeners[session]!);
      session.beforeConnect = null;
    }
    _attempts.clear();
    _listeners.clear();
    super.dispose();
  }

  void closeSessions({WorkspaceController? preserve}) {
    for (final session in _sessions) {
      if (!identical(session, preserve)) session.dispose();
    }
  }
}
