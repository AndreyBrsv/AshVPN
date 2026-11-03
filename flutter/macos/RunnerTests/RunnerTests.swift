import Cocoa
import CoreServices
import FlutterMacOS
import XCTest
@testable import Ashapp

class RunnerTests: XCTestCase {

  func testUpdateInstallerRejectsExternalAndLinkedFiles() throws {
    let cache = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/Application Support/Ashapp/updates", isDirectory: true)
    let folder = cache.appendingPathComponent("download-" + UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let file = folder.appendingPathComponent("synthetic.pkg")
    try Data("synthetic non-executable installer".utf8).write(to: file)
    XCTAssertNotNil(MainFlutterWindow.updateInstaller(path: file.path))
    try MainFlutterWindow.quarantineInstaller(file)
    var fresh = URL(fileURLWithPath: file.path)
    fresh.removeAllCachedResourceValues()
    let quarantine = try fresh.resourceValues(forKeys: [.quarantinePropertiesKey]).quarantineProperties
    XCTAssertFalse(quarantine?.isEmpty ?? true, "The downloaded installer must retain system quarantine.")
    XCTAssertEqual(try Data(contentsOf: file), Data("synthetic non-executable installer".utf8))
    let link = folder.appendingPathComponent("linked.pkg")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
    XCTAssertNil(MainFlutterWindow.updateInstaller(path: link.path))
    XCTAssertNil(MainFlutterWindow.updateInstaller(path: "/tmp/external.pkg"))
    XCTAssertNil(MainFlutterWindow.updateInstaller(path: folder.path))
  }

  func testExportDoesNotWriteThroughAnExistingReaderOrHardLink() throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let destination = directory.appendingPathComponent("existing")
    let alias = directory.appendingPathComponent("alias")
    try Data("old harmless data".utf8).write(to: destination)
    try FileManager.default.linkItem(at: destination, to: alias)
    let reader = try FileHandle(forReadingFrom: destination)
    defer { try? reader.close() }
    try MainFlutterWindow.savePrivateExport(path: destination.path, data: Data("new-private-placeholder".utf8))
    XCTAssertEqual(try reader.readToEnd(), Data("old harmless data".utf8))
    XCTAssertEqual(try String(contentsOf: alias, encoding: .utf8), "old harmless data")
    XCTAssertEqual(try String(contentsOf: destination, encoding: .utf8), "new-private-placeholder")
  }

  func testExportRejectsDirectoryAndLeavesItIntact() throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    XCTAssertThrowsError(try MainFlutterWindow.savePrivateExport(path: directory.path, data: Data("private-placeholder".utf8)))
    XCTAssertTrue(FileManager.default.fileExists(atPath: directory.path))
  }

  func testExportRestrictsExistingFileBeforeWriting() throws {
    let path = NSTemporaryDirectory() + UUID().uuidString
    defer { try? FileManager.default.removeItem(atPath: path) }
    FileManager.default.createFile(atPath: path, contents: Data(), attributes: [.posixPermissions: 0o644])
    try MainFlutterWindow.savePrivateExport(path: path, data: Data("test-private-placeholder".utf8))
    let attributes = try FileManager.default.attributesOfItem(atPath: path)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "test-private-placeholder")
  }

  func testExportRejectsSymlinks() throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let target = directory.appendingPathComponent("target")
    let link = directory.appendingPathComponent("link")
    try Data("unchanged".utf8).write(to: target)
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
    XCTAssertThrowsError(try MainFlutterWindow.savePrivateExport(path: link.path, data: Data("secret-placeholder".utf8)))
    XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "unchanged")
  }

}
