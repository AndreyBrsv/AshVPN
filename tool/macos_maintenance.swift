// Unsandboxed, separately launched maintenance UI. No network or secret access.
// The sandboxed host verifies the release; this helper rehashes the local PKG.
import Cocoa
import CryptoKit
import Darwin

enum MaintenanceError: Error { case refused }

func regularFile(_ url: URL) -> Bool {
  var info = stat()
  return url.resolvingSymlinksInPath() == url.standardizedFileURL &&
    lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG
}

func digest(_ file: URL) throws -> String {
  let stream = try FileHandle(forReadingFrom: file)
  defer { try? stream.close() }
  var hash = SHA256()
  while let bytes = try stream.read(upToCount: 1024 * 1024), !bytes.isEmpty {
    hash.update(data: bytes)
  }
  return hash.finalize().map { String(format: "%02x", $0) }.joined()
}

func shellQuote(_ value: String) -> String {
  return "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

func adminCommand(_ command: String) throws {
  // Quote an AppleScript string separately from each POSIX argument.
  let escaped = command.replacingOccurrences(of: "\\", with: "\\\\")
    .replacingOccurrences(of: "\"", with: "\\\"")
  var failure: NSDictionary?
  guard let script = NSAppleScript(source: "do shell script \"\(escaped)\" with administrator privileges") else {
    throw MaintenanceError.refused
  }
  script.executeAndReturnError(&failure)
  if failure != nil { throw MaintenanceError.refused }
}

let installedAppURL = URL(fileURLWithPath: "/Applications/Ashapp.app", isDirectory: true)
let appID = "io.github.andreybrsv.ashapp"

func installedApplication() -> Bool {
  return installedAppURL.resolvingSymlinksInPath().path == installedAppURL.standardizedFileURL.path &&
    Bundle(url: installedAppURL)?.bundleIdentifier == appID
}

func idleApplication() -> Bool {
  NSRunningApplication.runningApplications(withBundleIdentifier: appID).isEmpty
}

func runCleanup() throws {
  guard installedApplication(), idleApplication(),
        Bundle(url: installedAppURL)?.object(forInfoDictionaryKey: "AshappMaintenanceVersion") as? Int == 1 else {
    throw MaintenanceError.refused
  }
  let process = Process()
  process.executableURL = installedAppURL.appendingPathComponent("Contents/MacOS/Ashapp")
  process.arguments = ["--erase-local-data"]
  // Direct executable launches do not receive Launch Services' sandbox HOME.
  // Match the installed sandboxed app's normal settings location explicitly.
  var environment = ProcessInfo.processInfo.environment
  let containerHome = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Containers/\(appID)/Data").path
  environment["HOME"] = containerHome
  environment["CFFIXED_USER_HOME"] = containerHome
  process.environment = environment
  process.standardOutput = FileHandle.nullDevice
  process.standardError = FileHandle.nullDevice
  try process.run()
  let deadline = Date().addingTimeInterval(120)
  while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
  // Never remove the executable while a vault operation is still running.
  guard !process.isRunning, process.terminationStatus == 0 else { throw MaintenanceError.refused }
}

func install(_ package: URL, expected: String) throws {
  guard idleApplication(), regularFile(package), try digest(package) == expected else {
    throw MaintenanceError.refused
  }
  if FileManager.default.fileExists(atPath: installedAppURL.path) && !installedApplication() {
    throw MaintenanceError.refused
  }
  // Copy and rehash inside a root-owned 0700 staging directory AFTER system
  // authorization. A writable cache must not be swapped during that prompt.
  let command = "work=$(/usr/bin/mktemp -d /private/tmp/ashapp-update.XXXXXXXX) || exit 1; " +
    "trap '/bin/rm -rf -- \"$work\"' EXIT; " +
    "/usr/bin/ditto --rsrc --extattr " + shellQuote(package.path) + " \"$work/update.pkg\" && " +
    "test \"$(/usr/bin/shasum -a 256 \"$work/update.pkg\" | /usr/bin/cut -d ' ' -f 1)\" = " + shellQuote(expected) +
    " && /usr/sbin/installer -pkg \"$work/update.pkg\" -target /"
  try adminCommand(command)
  guard installedApplication() else { throw MaintenanceError.refused }
  guard NSWorkspace.shared.open(installedAppURL) else { throw MaintenanceError.refused }
}

final class MaintenanceDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
    do {
      let args = Array(CommandLine.arguments.dropFirst())
      if args.first == "--update" {
        guard args.count == 4, let pid = Int32(args[3]), pid > 0,
              args[2].range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              installedApplication() else { throw MaintenanceError.refused }
        let package = URL(fileURLWithPath: args[1])
        let folder = package.deletingLastPathComponent()
        // Only the host's canonical update cache, never an arbitrary command/file.
        guard let account = getpwuid(getuid()) else { throw MaintenanceError.refused }
        let home = String(cString: account.pointee.pw_dir)
        let caches = ["Library/Application Support/Ashapp/updates",
          "Library/Containers/\(appID)/Data/Library/Application Support/Ashapp/updates"]
          .map { URL(fileURLWithPath: home).appendingPathComponent($0).standardizedFileURL }
        guard package.pathExtension == "pkg", folder.lastPathComponent.hasPrefix("download-"),
              caches.contains(folder.deletingLastPathComponent()), regularFile(package),
              try digest(package) == args[2],
              let old = NSRunningApplication(processIdentifier: pid), old.bundleIdentifier == appID,
              old.bundleURL?.standardizedFileURL.path == installedAppURL.path else { throw MaintenanceError.refused }
        // Native host waits for readiness before it allows the installedAppURL to quit.
        try Data("ready".utf8).write(to: folder.appendingPathComponent("maintenance-ready"), options: .atomic)
        let deadline = Date().addingTimeInterval(60)
        while kill(pid, 0) == 0 && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
        guard kill(pid, 0) != 0, errno == ESRCH else { throw MaintenanceError.refused }
        try install(package, expected: args[2])
      } else {
        guard args.isEmpty else { throw MaintenanceError.refused }
        let exists = FileManager.default.fileExists(atPath: installedAppURL.path)
        guard !exists || installedApplication() else { throw MaintenanceError.refused }
        let alert = NSAlert()
        alert.messageText = exists ? "Maintain Ashapp" : "Install Ashapp"
        alert.informativeText = "Update keeps your local data. Uninstall never changes your VPS servers. Close Ashapp before continuing."
        alert.addButton(withTitle: exists ? "Update / Repair" : "Install")
        if exists { alert.addButton(withTitle: "Uninstall") }
        alert.addButton(withTitle: "Cancel")
        let erase = NSButton(checkboxWithTitle: "When uninstalling, also delete local data and saved passwords", target: nil, action: nil)
        erase.state = .off
        if exists && Bundle(url: installedAppURL)?.object(forInfoDictionaryKey: "AshappMaintenanceVersion") as? Int != 1 {
          erase.isEnabled = false
          erase.title = "Update this older app once before removing saved data too"
        }
        if exists { alert.accessoryView = erase }
        let choice = alert.runModal()
        if choice == .alertFirstButtonReturn {
          guard let package = Bundle.main.url(forResource: "Installation", withExtension: "pkg"),
                let expected = Bundle.main.object(forInfoDictionaryKey: "AshappPackageSHA256") as? String else {
            throw MaintenanceError.refused
          }
          try install(package, expected: expected)
        } else if exists && choice == .alertSecondButtonReturn {
          guard idleApplication(), installedApplication() else { throw MaintenanceError.refused }
          let confirm = NSAlert()
          confirm.messageText = "Uninstall Ashapp?"
          confirm.informativeText = erase.state == .on ? "Local settings, servers, templates and protected passwords will be deleted. Exported files and VPS servers remain unchanged." : "Saved servers, templates and passwords will stay on this computer."
          confirm.addButton(withTitle: "Cancel")
          confirm.addButton(withTitle: "Uninstall")
          if confirm.runModal() == .alertSecondButtonReturn {
            if erase.state == .on { try runCleanup() }
            guard idleApplication(), installedApplication() else { throw MaintenanceError.refused }
            // Fixed, identity-checked target; never a caller-provided recursive path.
            try adminCommand("/bin/rm -rf -- /Applications/Ashapp.app")
            guard !FileManager.default.fileExists(atPath: installedAppURL.path) else { throw MaintenanceError.refused }
          }
        }
      }
      // Let Launch Services deliver the relaunch before ending this helper.
      DispatchQueue.main.asyncAfter(deadline: .now() + 1) { NSApp.terminate(nil) }
    } catch {
      let alert = NSAlert()
      alert.messageText = "Ashapp maintenance could not finish"
      alert.informativeText = "Close all Ashapp windows and unlock protected storage, then retry. Authorization may have been cancelled. No server settings were changed. If updating, reopen the installed app and retry."
      alert.addButton(withTitle: "Close")
      alert.runModal()
      NSApp.terminate(nil)
    }
  }
}

let delegate = MaintenanceDelegate()
NSApplication.shared.delegate = delegate
NSApplication.shared.run()
