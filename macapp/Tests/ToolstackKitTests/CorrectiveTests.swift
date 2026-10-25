import XCTest
@testable import ToolstackKit
@testable import ToolstackApp

final class PendingTransport: URLProtocol {
    static var started: (() -> Void)?
    static var pending: PendingTransport?
    static var count = 0
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}
    override func startLoading() {
        Self.count += 1; Self.pending = self; Self.started?()
    }
    func failAfterEffect() {
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(#"{"detail":"receipt lost after effect"}"#.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
}

final class CorrectiveTests: XCTestCase {
    private func stubClient() -> ApiClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return ApiClient(baseURL: URL(string: "http://fake.invalid")!, session: URLSession(configuration: configuration))
    }
    override func tearDown() { StubURLProtocol.handler = nil; StubURLProtocol.failure = nil }

    @MainActor func testCommittedPolicy500ThenObservedMatchDoesNotReplay() async throws {
        var writes = 0
        let receipt = Data(#"{"name":"writer","enabled":["notes"],"policy":{"tools":{"notes":{"read":"allow"}}}}"#.utf8)
        StubURLProtocol.handler = { request in
            if request.httpMethod == "PUT" { writes += 1; return (500, [:], Data(#"{"detail":"lost acknowledgement"}"#.utf8)) }
            return (200, [:], receipt)
        }
        let model = AppModel(client: stubClient(), serverURL: "http://fake.invalid")
        var draft = PolicyDraft(caller: "writer")
        draft.load(try JSONDecoder().decode(PolicyResponse.self, from: receipt))
        draft = await model.writePolicy(draft)
        XCTAssertEqual(draft.phase, .unknown)
        XCTAssertFalse(draft.canSave)
        let observed = await model.loadPolicy(for: "writer")
        draft.compare(try XCTUnwrap(observed))
        XCTAssertEqual(draft.phase, .saved)
        _ = await model.writePolicy(draft)
        XCTAssertEqual(writes, 1)
    }

    @MainActor func testListingErrorPreservesRowsAndFailedCompareRetainsUnknown() async throws {
        let row = try JSONDecoder().decode(ToolInfo.self, from: Data(#"{"id":"retained","running":true,"alive":true}"#.utf8))
        StubURLProtocol.handler = { request in
            if request.url?.path == "/api/broker" { return (200, [:], Data(#"{"running":true}"#.utf8)) }
            return (200, [:], Data(#"{"tools":[],"error":"fixture inspection failure"}"#.utf8))
        }
        let model = AppModel(client: stubClient(), serverURL: "http://fake.invalid")
        model.tools = [row]
        let loaded = await model.refreshTools()
        XCTAssertFalse(loaded); XCTAssertEqual(model.tools.map(\.id), ["retained"])
        XCTAssertNotNil(model.toolsError)
        model.uncertainMutation = "Restart retained: unknown"
        await model.compareMutationState()
        XCTAssertNotNil(model.uncertainMutation); XCTAssertFalse(model.effectInFlight)
    }

    @MainActor func testSameIdentityUnauthorizedPreservesDraftAndEnabledComparisonInputs() async {
        StubURLProtocol.handler = { _ in (401, [:], Data()) }
        let model = AppModel(client: stubClient(), serverURL: "http://fake.invalid")
        model.policyDrafts["writer"] = PolicyDraft(caller: "writer")
        model.enabledDrafts["writer"] = ["hidden", "local"]
        model.enabledBaselines["writer"] = ["hidden"]
        model.enabledOutcomes["writer"] = .unknown
        let response = await model.loadPolicy(for: "writer")
        XCTAssertNil(response)
        XCTAssertNotNil(model.policyDrafts["writer"])
        XCTAssertEqual(model.enabledDrafts["writer"], ["hidden", "local"])
        XCTAssertEqual(model.enabledOutcomes["writer"], .unknown)
    }

    func testEnablementMergeCases() {
        XCTAssertEqual(EnabledToolsMerge.reconcile(baseline: ["a"], local: ["a"], remote: ["a", "new"]), ["a", "new"])
        XCTAssertEqual(EnabledToolsMerge.reconcile(baseline: ["a", "removed"], local: ["a", "removed"], remote: ["a"]), ["a"])
        XCTAssertEqual(EnabledToolsMerge.reconcile(baseline: ["disable", "hidden"], local: ["hidden"], remote: ["disable", "hidden", "new"]), ["hidden", "new"])
        XCTAssertEqual(EnabledToolsMerge.reconcile(baseline: ["a"], local: ["a", "b"], remote: ["a", "b"]), ["a", "b"])
    }
    @MainActor func testEnablement500ThenMatchingReadNeedsNoSecondWrite() async throws {
        var writes = 0
        StubURLProtocol.handler = { request in
            if request.httpMethod == "PUT" { writes += 1; return (500, [:], Data()) }
            return (200, [:], Data(#"{"name":"writer","enabled":["hidden","local"],"policy":{"tools":{}}}"#.utf8))
        }
        let model = AppModel(client: stubClient(), serverURL: "http://fake.invalid")
        let result = await model.setEnabledTools(caller: "writer", enabled: ["hidden", "local"])
        XCTAssertEqual(result, .unknown)
        let read = await model.loadPolicy(for: "writer")
        XCTAssertEqual(Set(try XCTUnwrap(read).enabled), ["hidden", "local"])
        XCTAssertEqual(writes, 1)
    }
    func testConservativeHTTPClassification() {
        for code in [408, 409, 429, 500, 502, 503, 504] {
            XCTAssertEqual(MutationResult(error: ApiError.http(status: code, message: "fake")), .unknown)
        }
        XCTAssertEqual(MutationResult(error: ApiError.http(status: 400, message: "validation")), .rejected)
        XCTAssertEqual(MutationResult(error: ApiError.unauthorized), .rejected)
    }
    func testThreeWayEnablementPreservesRemoteChanges() {
        XCTAssertEqual(EnabledToolsMerge.reconcile(baseline: ["a", "hidden", "removed"], local: ["hidden", "removed", "local"], remote: ["a", "hidden", "new"]), ["hidden", "new", "local"])
    }
    @MainActor func testToolAndBrokerPendingEffectsAreSingleFlight() async {
        for broker in [false, true] {
            PendingTransport.count = 0
            let started = expectation(description: "POST pending")
            PendingTransport.started = { started.fulfill() }
            let config = URLSessionConfiguration.ephemeral
            config.protocolClasses = [PendingTransport.self]
            let model = AppModel(client: ApiClient(baseURL: URL(string: "http://fake.invalid")!, session: URLSession(configuration: config)), serverURL: "http://fake.invalid")
            let task = Task {
                if broker { await model.brokerAction("restart", confirmed: true) }
                else { await model.toolAction(id: "fake", action: "restart", confirmed: true) }
            }
            await fulfillment(of: [started], timeout: 2)
            XCTAssertTrue(model.effectInFlight)
            await model.brokerAction("restart", confirmed: true)
            await model.toolAction(id: "fake", action: "restart", confirmed: true)
            XCTAssertEqual(PendingTransport.count, 1)
            PendingTransport.pending?.failAfterEffect()
            await task.value
            XCTAssertNotNil(model.uncertainMutation)
            XCTAssertFalse(model.effectInFlight)
            await model.toolAction(id: "fake", action: "restart", confirmed: true)
            XCTAssertEqual(PendingTransport.count, 1)
        }
        PendingTransport.pending = nil; PendingTransport.started = nil
    }
    @MainActor func testAdminScopedStateResetWithoutCredentialAccess() {
        let model = AppModel(client: ApiClient(baseURL: URL(string: "http://fake.invalid")!), serverURL: "http://fake.invalid")
        model.uncertainMutation = "unknown"; model.busy = true; model.banner = "fake"; model.error = "fake"
        model.confirmation = .init(title: "fake", effect: "fake", action: {})
        model.policyDrafts["writer"] = PolicyDraft(caller: "writer")
        model.clearAdminState()
        XCTAssertNil(model.uncertainMutation); XCTAssertNil(model.confirmation)
        XCTAssertNil(model.error); XCTAssertNil(model.banner); XCTAssertFalse(model.busy)
        XCTAssertTrue(model.tools.isEmpty); XCTAssertTrue(model.policyDrafts.isEmpty)
    }
}
