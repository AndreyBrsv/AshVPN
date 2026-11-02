import Cocoa
import FlutterMacOS
import XCTest
@testable import Ashapp

class RunnerTests: XCTestCase {

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
