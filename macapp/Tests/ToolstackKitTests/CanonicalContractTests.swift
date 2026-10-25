import Foundation
import XCTest
@testable import ToolstackKit

final class CanonicalContractTests: XCTestCase {
    func testOwnershipUnknownIsNotManaged() throws {
        let decoder = JSONDecoder()
        let unknown = try decoder.decode(ToolInfo.self, from: Data(#"{"id":"unknown"}"#.utf8))
        XCTAssertNil(unknown.removable)
        let external = try decoder.decode(ToolInfo.self, from: Data(#"{"id":"external","removable":true,"path":"/fake/external"}"#.utf8))
        XCTAssertEqual(external.removable, true)
        XCTAssertEqual(external.path, "/fake/external")
    }
    // Source regression guard only; behavioral proof is in transport/state tests.
    func testUnsupportedProvisioningSignifiersRemoved() throws {
        let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Sources")
        let paths = ["ToolstackApp/ToolstackApp.swift", "ToolstackApp/AppModel.swift", "ToolstackKit/ApiClient.swift", "ToolstackKit/Models.swift"]
        for path in paths {
            let text = try String(contentsOf: sources.appendingPathComponent(path))
            for forbidden in ["setSecretValue", "SetSecretResult", "SecretValuesSheet", "Set values...", "clearAudit"] {
                XCTAssertFalse(text.contains(forbidden), "\(path): \(forbidden)")
            }
        }
    }
    func testCanonicalNativeContract() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("admin/tests/fixtures/native_api.json"))
        let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let backend = try decoder.decode(SecretBackend.self, from: JSONSerialization.data(withJSONObject: fixture["backend"]!))
        XCTAssertEqual(backend.plugin, "localfile")
        let secrets = try decoder.decode(SecretStatus.self, from: JSONSerialization.data(withJSONObject: fixture["secret_status"]!))
        XCTAssertNil(secrets.provisioned)
        XCTAssertEqual(secrets.availability, "Unknown")
        XCTAssertEqual(secrets.status, "UNKNOWN")
        XCTAssertFalse(secrets.settable)
        let states = try XCTUnwrap(fixture["tool_states"] as? [[String: Any]])
        let expected = ["Alive", "Failed", "Stopped", "Unknown"]
        for (index, state) in states.enumerated() {
            var row = state
            row["id"] = "fake-tool"
            let tool = try decoder.decode(ToolInfo.self, from: JSONSerialization.data(withJSONObject: row))
            XCTAssertEqual(tool.observedStatus, expected[index])
            XCTAssertEqual(tool.state, state["state"] as? String)
            XCTAssertEqual(tool.health, state["health"] as? String)
        }
    }
}
