import XCTest
@testable import ToolstackKit
@testable import ToolstackApp

final class PolicyDraftTests: XCTestCase {
    private func response() throws -> PolicyResponse {
        try JSONDecoder().decode(PolicyResponse.self, from: Data(#"{"name":"writer","enabled":["notes","other"],"policy":{"tools":{"notes":{"read":"allow"},"other":{"write":"review"}}}}"#.utf8))
    }
    func testLoadGate() {
        var draft = PolicyDraft(caller: "writer")
        XCTAssertFalse(draft.beginSave())
        draft.loadFailed()
        XCTAssertFalse(draft.canSave)
        XCTAssertFalse(draft.beginSave())
    }
    func testRejectedSaveRetainsTargetAndOtherGrants() throws {
        var draft = PolicyDraft(caller: "writer")
        draft.load(try response())
        draft.set(.review, for: "notes.read")
        XCTAssertTrue(draft.beginSave())
        draft.failed(ApiError.http(status: 400, message: "validation rejected"))
        XCTAssertEqual(draft.caller, "writer")
        XCTAssertEqual(draft.effects["other.write"], .review)
        XCTAssertEqual(draft.effects["notes.read"], .review)
        XCTAssertTrue(draft.dirty)
        XCTAssertTrue(draft.canSave)
    }
    func testUnknownRequiresCompareBeforeRetry() throws {
        var draft = PolicyDraft(caller: "writer")
        draft.load(try response())
        draft.set(.allow, for: "notes.write")
        XCTAssertTrue(draft.beginSave())
        draft.failed(ApiError.transport("timeout"))
        XCTAssertEqual(draft.phase, .unknown)
        XCTAssertFalse(draft.beginSave())
        draft.compare(try response())
        XCTAssertEqual(draft.phase, .conflict)
        XCTAssertEqual(draft.effects["notes.write"], .allow)
    }
    func testCompareMatchesWithoutReplay() throws {
        var draft = PolicyDraft(caller: "writer")
        draft.load(try response())
        XCTAssertTrue(draft.beginSave())
        draft.failed(ApiError.decoding("lost receipt"))
        draft.compare(try response())
        XCTAssertEqual(draft.phase, .saved)
        XCTAssertFalse(draft.canSave)
    }
    func testComparisonPreservesConcurrentUneditedGrants() throws {
        var draft = PolicyDraft(caller: "writer")
        draft.load(try response())
        draft.set(.review, for: "notes.read")
        let remote = try JSONDecoder().decode(PolicyResponse.self, from: Data(#"{"name":"writer","enabled":["notes","other"],"policy":{"tools":{"notes":{"read":"allow"},"other":{"write":"allow","new":"review"}}}}"#.utf8))
        draft.compare(remote)
        XCTAssertEqual(draft.effects["notes.read"], .review)
        XCTAssertEqual(draft.effects["other.write"], .allow)
        XCTAssertEqual(draft.effects["other.new"], .review)
    }
    func testMemoryDraftRetainsTargetAcrossNavigation() throws {
        var draft = PolicyDraft(caller: "writer")
        draft.load(try response())
        draft.set(.review, for: "notes.read")
        let memory = [draft.caller: draft]
        let resumed = try XCTUnwrap(memory["writer"])
        XCTAssertTrue(resumed.dirty)
        XCTAssertEqual(resumed.effects["notes.read"], .review)
        XCTAssertNil(memory["another-caller"])
    }
    @MainActor func testWriteUsesMatchingAndDivergentReceiptsIncludingEnabledState() async throws {
        for (policy, expectedPhase) in [
            (#"{"notes":{"read":"review"},"other":{"write":"review"}}"#, PolicyDraft.Phase.saved),
            (#"{"notes":{"read":"allow"},"other":{"write":"review"}}"#, .conflict),
            (#"{"other":{"write":"review"}}"#, .conflict)
        ] {
            var requests = 0
            StubURLProtocol.handler = { request in
                requests += 1
                XCTAssertEqual(request.httpMethod, "PUT")
                XCTAssertEqual(request.url?.path, "/api/callers/writer/policy")
                return (200, [:], Data("{\"name\":\"writer\",\"enabled\":[\"remote-only\"],\"policy\":{\"tools\":\(policy)}}".utf8))
            }
            let model = makeModel()
            var draft = PolicyDraft(caller: "writer")
            draft.load(try response())
            draft.set(.review, for: "notes.read")
            let result = await model.writePolicy(draft)
            XCTAssertEqual(result.phase, expectedPhase)
            XCTAssertEqual(result.enabled, ["remote-only"])
            XCTAssertEqual(result.effects["notes.read"], .review)
            XCTAssertEqual(result.effects["other.write"], .review)
            XCTAssertEqual(result.dirty, expectedPhase == .conflict)
            XCTAssertEqual(model.policyDrafts["writer"]?.phase, expectedPhase)
            XCTAssertEqual(requests, 1, "Use the receipt; no second GET or replay")
        }
    }
    @MainActor func testWrongCallerReceiptIsUnknownAndDoesNotApply() async throws {
        var requests = 0
        StubURLProtocol.handler = { _ in
            requests += 1
            return (200, [:], Data(#"{"name":"someone-else","enabled":["alien"],"policy":{"tools":{}}}"#.utf8))
        }
        let model = makeModel()
        var draft = PolicyDraft(caller: "writer")
        draft.load(try response())
        draft.set(.review, for: "notes.read")
        let result = await model.writePolicy(draft)
        XCTAssertEqual(result.phase, .unknown)
        XCTAssertEqual(result.effects, draft.effects)
        XCTAssertEqual(result.baseline, draft.baseline)
        XCTAssertEqual(result.enabled, draft.enabled)
        XCTAssertFalse(result.canSave)
        let retry = await model.writePolicy(result)
        XCTAssertEqual(retry.phase, .unknown)
        XCTAssertEqual(requests, 1)
        XCTAssertNil(model.policyDrafts["someone-else"])
    }
    @MainActor private func makeModel() -> AppModel {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        return AppModel(client: ApiClient(baseURL: URL(string: "http://fake.invalid")!, session: URLSession(configuration: config)), serverURL: "http://fake.invalid")
    }
    override func tearDown() { StubURLProtocol.handler = nil; StubURLProtocol.failure = nil }
}
