import Cocoa
import FlutterMacOS
import Darwin
import CoreServices

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)
    self.contentMinSize = NSSize(width: 420, height: 480)
    var initialSize = NSSize(width: 520, height: 760)
    if let visible = (self.screen ?? NSScreen.main)?.visibleFrame {
      let titleHeight = self.frame.height - self.contentRect(forFrameRect: self.frame).height
      initialSize.width = max(420, min(initialSize.width, visible.width - 24))
      initialSize.height = max(480, min(initialSize.height, visible.height - titleHeight - 24))
    }
    self.setContentSize(initialSize)
    self.center()

    RegisterGeneratedPlugins(registry: flutterViewController)
    let updates = FlutterMethodChannel(name: "ashapp/app-update",
                                      binaryMessenger: flutterViewController.engine.binaryMessenger)
    updates.setMethodCallHandler { call, result in
      switch call.method {
      case "maintenanceRequested":
        let requested = CommandLine.arguments.contains("--erase-local-data")
        if requested && NSRunningApplication.runningApplications(withBundleIdentifier: "io.github.andreybrsv.ashapp")
          .contains(where: { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }) {
          result(FlutterError(code: "maintenance_busy", message: "Close Ashapp before uninstalling.", details: nil))
        } else { result(requested) }
      case "info":
        #if arch(arm64)
        let target = "macos-arm64"
        #else
        let target = "macos-x64"
        #endif
        result(["version": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "",
                "target": target])
      case "openInstaller":
        guard let args = call.arguments as? [String: Any], let path = args["path"] as? String,
              let installer = MainFlutterWindow.updateInstaller(path: path),
              let hash = args["sha256"] as? String,
              hash.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              Bundle.main.bundleURL.path == "/Applications/Ashapp.app" else {
          result(FlutterError(code: "update_failed", message: "Invalid installer.", details: nil))
          return
        }
        do { try MainFlutterWindow.quarantineInstaller(installer) } catch {
          result(FlutterError(code: "update_failed", message: "Could not apply macOS download security policy.", details: nil))
          return
        }
        MainFlutterWindow.startBackgroundUpdate(installer, hash: hash, result: result)
      case "quit":
        result(nil)
        DispatchQueue.main.async { NSApplication.shared.terminate(nil) }
      default: result(FlutterMethodNotImplemented)
      }
    }
    let exports = FlutterMethodChannel(name: "ashapp/private-export",
                                      binaryMessenger: flutterViewController.engine.binaryMessenger)
    exports.setMethodCallHandler { call, result in
      guard call.method == "save", let args = call.arguments as? [String: Any],
            let path = args["path"] as? String,
            let bytes = args["bytes"] as? FlutterStandardTypedData else {
        result(FlutterMethodNotImplemented)
        return
      }
      do {
        try MainFlutterWindow.savePrivateExport(path: path, data: bytes.data)
        result(nil)
      } catch {
        result(FlutterError(code: "export_failed", message: "Could not save private configuration.", details: nil))
      }
    }

    super.awakeFromNib()
  }

  static func startBackgroundUpdate(_ installer: URL, hash: String, result: @escaping FlutterResult) {
    let manager = FileManager.default
    let folder = installer.deletingLastPathComponent()
    let helper = folder.appendingPathComponent("Ashapp Maintenance.app", isDirectory: true)
    let ready = folder.appendingPathComponent("maintenance-ready")
    do {
      let source = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/Ashapp Maintenance.app")
      guard manager.fileExists(atPath: source.path),
            !manager.fileExists(atPath: helper.path), !manager.fileExists(atPath: ready.path) else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
      }
      // The helper must outlive replacement of the original .app bundle.
      try manager.copyItem(at: source, to: helper)
    } catch {
      result(FlutterError(code: "update_failed", message: "Update helper is unavailable. Re-download the app or use the installer.", details: nil))
      return
    }
    let configuration = NSWorkspace.OpenConfiguration()
    configuration.arguments = ["--update", installer.path, hash, String(ProcessInfo.processInfo.processIdentifier)]
    configuration.activates = false
    configuration.createsNewApplicationInstance = true
    NSWorkspace.shared.openApplication(at: helper, configuration: configuration) { application, error in
      DispatchQueue.main.async {
        guard error == nil, let application = application else {
          try? manager.removeItem(at: helper)
          result(FlutterError(code: "update_failed", message: "Could not start the update helper.", details: nil))
          return
        }
        let deadline = Date().addingTimeInterval(30)
        Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { timer in
          if (try? String(contentsOf: ready, encoding: .utf8)) == "ready" {
            timer.invalidate()
            result(nil)
          } else if application.isTerminated || Date() >= deadline {
            timer.invalidate()
            // Before readiness the parent is still alive, so installation has
            // not started. Cancel only our own helper, never a server task.
            application.forceTerminate()
            result(FlutterError(code: "update_failed", message: "The update helper was not ready. Close any maintenance window and retry.", details: nil))
          }
        }
      }
    }
  }

  static func updateInstaller(path: String) -> URL? {
    guard path.hasPrefix("/"), !path.utf8.contains(0) else { return nil }
    let file = URL(fileURLWithPath: path)
    let cache = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/Application Support/Ashapp/updates", isDirectory: true)
      .resolvingSymlinksInPath()
    var info = stat()
    guard file.pathExtension == "pkg", file.deletingLastPathComponent().lastPathComponent.hasPrefix("download-"),
          file.deletingLastPathComponent().deletingLastPathComponent().resolvingSymlinksInPath() == cache,
          file.resolvingSymlinksInPath() == file.standardizedFileURL,
          lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
    return file
  }

  static func quarantineInstaller(_ file: URL) throws {
    func currentProperties() throws -> [String: Any]? {
      var fresh = URL(fileURLWithPath: file.path)
      fresh.removeAllCachedResourceValues()
      return try fresh.resourceValues(forKeys: [.quarantinePropertiesKey]).quarantineProperties
    }
    // Preserve existing system quarantine and user-approval metadata. Sandbox
    // may normalize/omit the type, so its exact value is not a security test.
    if let existing = try currentProperties(), !existing.isEmpty { return }
    var url = URL(fileURLWithPath: file.path)
    let properties: [String: Any] = [
      kLSQuarantineTypeKey as String: kLSQuarantineTypeWebDownload as String,
      kLSQuarantineOriginURLKey as String: URL(string: "https://github.com/AndreyBrsv/Ashapp/releases/latest")!
    ]
    var values = URLResourceValues()
    values.quarantineProperties = properties
    try url.setResourceValues(values)
    guard let applied = try currentProperties(), !applied.isEmpty else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(EPERM))
    }
  }

  static func savePrivateExport(path: String, data: Data) throws {
    guard path.hasPrefix("/"), !path.utf8.contains(0), data.count <= 1024 * 1024 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
    }
    var original = stat()
    if lstat(path, &original) == 0 {
      guard (original.st_mode & S_IFMT) == S_IFREG else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
      }
    } else if errno != ENOENT {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    let destination = URL(fileURLWithPath: path)
    let parent = destination.deletingLastPathComponent().resolvingSymlinksInPath()
    let coordinator = NSFileCoordinator()
    var coordinationError: NSError?
    var writingError: Error?
    // Use a sandbox-aware replacement directory, not an arbitrary sibling of
    // the file selected in the save panel. Never rewrite an old readable inode.
    coordinator.coordinate(writingItemAt: destination, options: .forReplacing,
                           error: &coordinationError) { selected in
      do {
        guard selected.lastPathComponent == destination.lastPathComponent,
              selected.deletingLastPathComponent().resolvingSymlinksInPath() == parent else {
          throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
        }
        func checkDestination() throws {
          var previous = stat()
          if lstat(selected.path, &previous) == 0 {
            guard (previous.st_mode & S_IFMT) == S_IFREG else {
              throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
            }
          } else if errno != ENOENT {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
          }
        }
        try checkDestination()
        let manager = FileManager.default
        let folder = try manager.url(for: .itemReplacementDirectory, in: .userDomainMask,
                                     appropriateFor: selected, create: true)
        defer { try? manager.removeItem(at: folder) }
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path)
        let staging = folder.appendingPathComponent(UUID().uuidString)
        let fd = Darwin.open(staging.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                             mode_t(0o600))
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(), info.st_nlink == 1,
              let acl = acl_init(0) else {
          throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_set_fd(fd, acl) == 0, fchmod(fd, mode_t(0o600)) == 0 else {
          throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        try data.withUnsafeBytes { buffer in
          var offset = 0
          while offset < buffer.count {
            let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
            offset += count
          }
        }
        guard fsync(fd) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        try checkDestination()
        // Same-volume rename preserves the fresh private inode and its ACL.
        guard Darwin.rename(staging.path, selected.path) == 0 else {
          throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
      } catch {
        writingError = error
      }
    }
    if let error = coordinationError { throw error }
    if let error = writingError { throw error }
  }
}
