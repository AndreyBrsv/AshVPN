import Cocoa
import FlutterMacOS
import Darwin

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)
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

  static func savePrivateExport(path: String, data: Data) throws {
    // O_NOFOLLOW prevents following a substituted symlink. Restrict the actual
    // opened inode before truncation/writing; chmod(path) would have a race.
    let fd = Darwin.open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, mode_t(0o600))
    guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
    defer { Darwin.close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
          fchmod(fd, mode_t(0o600)) == 0, ftruncate(fd, 0) == 0 else {
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
  }
}
