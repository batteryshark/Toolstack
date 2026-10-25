import XCTest
@testable import ToolstackKit

final class CallerSettingsTests: XCTestCase {
    func snapshot(revision: String = "one", installation: String = "fake-installation") throws -> SettingsSnapshot {
        let catalog = Dictionary(uniqueKeysWithValues: (0..<30).map { tool in
            (String(format: "tool%02d", tool), (0..<20).map { op in
                ["op": String(format: "fn%02d", op), "risk": "read", "description": "fake function"]
            })
        })
        let json: [String: Any] = ["name": "writer-demo", "caller_id": 1, "operator": "admin", "installation": installation, "revision": revision,
                                  "enabled": ["tool00"], "policy": ["tools": ["tool00": ["fn00": "review"]]], "catalog": catalog]
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(SettingsSnapshot.self, from: JSONSerialization.data(withJSONObject: json))
    }
    func testWholeToolDefaultsAndFunctionExclusionsRetainPolicy() throws {
        var draft = CallerSettingsDraft(try snapshot())
        draft.setTool("tool01", enabled: true)
        XCTAssertEqual(draft.matches("tool01").filter { draft.values.active("tool01", $0.op) }.count, 20)
        XCTAssertEqual(draft.values.effect("tool01", "fn00"), "deny")
        draft.setFunction("tool00", "fn00", enabled: false)
        XCTAssertFalse(draft.values.active("tool00", "fn00"))
        XCTAssertEqual(draft.values.effect("tool00", "fn00"), "review")
        draft.setTool("tool00", enabled: false)
        draft.setFunction("tool00", "fn01", enabled: true)
        XCTAssertTrue(draft.values.active("tool00", "fn01"))
        XCTAssertFalse(draft.values.active("tool00", "fn00"))
    }
    func test600FunctionsSearchAndFilteredBulkScope() throws {
        var draft = CallerSettingsDraft(try snapshot())
        XCTAssertEqual(draft.snapshot.catalog.values.reduce(0) { $0 + $1.count }, 600)
        draft.search = "fn01"
        XCTAssertEqual(draft.snapshot.catalog.keys.reduce(0) { $0 + draft.matches($1).count }, 30)
        draft.bulk("tool01", enabled: true)
        XCTAssertTrue(draft.values.active("tool01", "fn01"))
        XCTAssertFalse(draft.values.active("tool01", "fn00"))
        draft.search = ""; draft.enabledOnly = true
        draft.bulk("tool00", enabled: false)
        XCTAssertEqual(draft.matches("tool00").count, 0)
        draft.enabledOnly = false; draft.needsReview = true
        XCTAssertEqual(draft.matches("tool00").map(\.op), ["fn00"])
    }
    func testComparingNeverChangesDraftAndExplicitRebasePreservesRemoteEdits() throws {
        var draft = CallerSettingsDraft(try snapshot())
        draft.values.tools["tool00"]?["fn00"] = "deny"
        draft.setFunction("tool00", "fn02", enabled: false)
        let before = draft.values
        var remote = try snapshot(revision: "two")
        remote.policy.tools?["tool00"]?["fn01"] = "allow"
        draft.observe(remote)
        XCTAssertEqual(draft.phase, .stale); XCTAssertFalse(draft.canSave)
        XCTAssertFalse(draft.differences(remote).isEmpty)
        XCTAssertEqual(draft.values, before)
        XCTAssertTrue(draft.keepEdits(on: remote))
        XCTAssertEqual(draft.values.effect("tool00", "fn01"), "allow")
        XCTAssertEqual(draft.values.effect("tool00", "fn00"), "deny")
        XCTAssertFalse(draft.values.active("tool00", "fn02"))
        XCTAssertTrue(draft.canSave)
    }
    func testDifferentInstallationDoesNotRebase() throws {
        var draft = CallerSettingsDraft(try snapshot())
        draft.setTool("tool01", enabled: true)
        let before = draft
        XCTAssertFalse(draft.keepEdits(on: try snapshot(installation: "different")))
        XCTAssertEqual(draft, before)
    }
    func testDurableDraftIsPrivateScopedAndInterruptedSaveCannotReplay() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = SettingsDraftStore(directory: root)
        let remote = try snapshot()
        var draft = CallerSettingsDraft(remote)
        draft.setTool("tool01", enabled: true); draft.values.tools["tool01"]?["fn01"] = "allow"
        draft.tab = "policy"; draft.search = "fn01"; draft.phase = .saving
        try store.save(draft, account: "http://fake.invalid")
        let restored = try XCTUnwrap(store.load(account: "http://fake.invalid", snapshot: remote))
        XCTAssertEqual(restored.values, draft.values); XCTAssertEqual(restored.tab, "policy")
        XCTAssertEqual(restored.search, "fn01"); XCTAssertEqual(restored.phase, .unknown); XCTAssertFalse(restored.canSave)
        XCTAssertNil(try store.load(account: "http://other.invalid", snapshot: remote))
        let file = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil).first)
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        draft.search = "second write"; try store.save(draft, account: "http://fake.invalid")
        XCTAssertEqual(try store.load(account: "http://fake.invalid", snapshot: remote)?.search, "second write")
        try store.discard(account: "http://fake.invalid", snapshot: remote)
        XCTAssertNil(try store.load(account: "http://fake.invalid", snapshot: remote))
    }

    func testRemovedFunctionsRetainTheOriginalDraft() throws {
        var draft = CallerSettingsDraft(try snapshot())
        draft.values.tools["tool00"]?["fn01"] = "allow"
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(draft.snapshot)) as? [String: Any])
        var catalog = try XCTUnwrap(json["catalog"] as? [String: [[String: String]]])
        catalog["tool00"] = catalog["tool00"]?.filter { $0["op"] != "fn01" }
        json["catalog"] = catalog; json["revision"] = "two"
        let remote = try JSONDecoder().decode(SettingsSnapshot.self, from: JSONSerialization.data(withJSONObject: json))
        let before = draft
        XCTAssertFalse(draft.keepEdits(on: remote))
        XCTAssertEqual(draft, before)
        XCTAssertTrue(draft.differences(remote).contains { $0.latest == "No longer available" })
    }

    func testReceiptMustMatchBothTabsAndTarget() throws {
        var draft = CallerSettingsDraft(try snapshot())
        draft.values.tools["tool00"]?["fn01"] = "allow"; draft.setTool("tool01", enabled: true)
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        let wrong = try decoder.decode(SettingsReceipt.self, from: Data(#"{"outcome":"saved","name":"writer-demo","policy":{"enabled":["tool00"],"tools":{}}}"#.utf8))
        XCTAssertThrowsError(try draft.accept(wrong))
        XCTAssertTrue(draft.dirty)
        let payload: [String: Any] = ["outcome": "saved", "name": "writer-demo", "policy": [
            "enabled": draft.values.enabled.sorted(), "tools": draft.values.tools,
            "disabled_functions": draft.values.excluded.mapValues { $0.sorted() }
        ]]
        let receipt = try decoder.decode(SettingsReceipt.self, from: JSONSerialization.data(withJSONObject: payload))
        try draft.accept(receipt)
        XCTAssertEqual(draft.phase, .saved); XCTAssertFalse(draft.dirty); XCTAssertFalse(draft.canSave)
    }
}
