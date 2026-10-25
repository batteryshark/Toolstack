import XCTest
@testable import ToolstackKit
@testable import ToolstackApp

final class ActiveRefreshTests: XCTestCase {
    private let account = "http://refresh.invalid"
    private func client(pending: Bool = false) -> ApiClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = pending ? [PendingTransport.self] : [StubURLProtocol.self]
        return ApiClient(baseURL: URL(string: account)!, session: URLSession(configuration: configuration), token: "FAKE-TEST-TOKEN")
    }
    private func stub() {
        StubURLProtocol.requestCount = 0
        StubURLProtocol.handler = { request in
            let json: String
            switch request.url!.path {
            case "/api/broker": json = #"{"running":true}"#
            case "/api/callers": json = #"{"callers":[{"id":1,"name":"demo","revoked_at":123}]}"#
            case "/api/tools": json = #"{"tools":[]}"#
            default: XCTFail("Unexpected request: \(request)"); json = "{}"
            }
            return (200, [:], Data(json.utf8))
        }
    }
    @MainActor func testActivationAndActiveTickObserveRevocationPreservingDraftsAndConfirmation() async throws {
        stub()
        let model = AppModel(client: client(), serverURL: account)
        model.authenticated = true
        model.callers = try JSONDecoder().decode(CallersResponse.self, from: Data(#"{"callers":[{"id":1,"name":"demo"}]}"#.utf8)).callers
        var draft = PolicyDraft(caller: "demo")
        draft.set(.allow, for: "demo.read")
        model.policyDrafts["demo"] = draft
        model.enabledDrafts["demo"] = ["demo"]
        model.confirmation = .init(title: "Existing confirmation", effect: "Keep", action: {})
        model.uncertainMutation = "Outcome unknown"
        let epoch = model.generation
        await model.refreshWhileActive(false)
        XCTAssertEqual(StubURLProtocol.requestCount, 0)
        await model.refreshWhileActive(true)
        XCTAssertEqual(StubURLProtocol.requestCount, 3)
        XCTAssertFalse(try XCTUnwrap(model.callers.first).isActive)
        XCTAssertEqual(model.policyDrafts["demo"]?.effects, draft.effects)
        XCTAssertEqual(model.enabledDrafts["demo"], ["demo"])
        XCTAssertEqual(model.generation, epoch, "Stable view identity keeps open editors mounted")
        XCTAssertEqual(model.confirmation?.title, "Existing confirmation")
        XCTAssertEqual(model.uncertainMutation, "Outcome unknown")
        await model.refreshWhileActive(true)
        XCTAssertEqual(StubURLProtocol.requestCount, 6)
    }
    @MainActor func testRevokedCallerCannotPresentRevokeOrRotateConfirmation() async {
        stub()
        let model = AppModel(client: client(), serverURL: account)
        model.authenticated = true
        let allowed = await model.prepareCallerConfirmation("demo")
        XCTAssertFalse(allowed)
        await model.rotateToken(caller: "demo")
        XCTAssertNil(model.confirmation)
        XCTAssertEqual(StubURLProtocol.requestCount, 6)
    }
    @MainActor func testConcurrentRefreshesCoalesce() async {
        PendingTransport.count = 0
        let model = AppModel(client: client(pending: true), serverURL: account)
        model.authenticated = true
        let started = expectation(description: "Broker read held")
        PendingTransport.started = {
            switch PendingTransport.count {
            case 1: started.fulfill()
            case 2: PendingTransport.pending?.respond(200, #"{"callers":[]}"#)
            case 3: PendingTransport.pending?.respond(200, #"{"tools":[]}"#)
            default: XCTFail("Overlapping refresh")
            }
        }
        let first = Task { await model.refreshAll() }
        await fulfillment(of: [started], timeout: 2)
        let joined = expectation(description: "Second refresh joined")
        let second = Task { joined.fulfill(); await model.refreshAll() }
        await fulfillment(of: [joined], timeout: 2)
        XCTAssertEqual(PendingTransport.count, 1)
        PendingTransport.pending?.respond(200, #"{"running":true}"#)
        await first.value; await second.value
        XCTAssertEqual(PendingTransport.count, 3)
    }
    @MainActor func testSignOutDeletesStoredTokenClearsClientAndReturnsToLoginWithoutServerLogout() async throws {
        stub()
        let api = client()
        var tokens = [account: "FAKE-TEST-TOKEN"]
        var deleted: [String] = []
        let storage = TokenStorage(save: { tokens[$1] = $0 }, load: { tokens[$0] }, delete: {
            deleted.append($0); tokens[$0] = nil
        })
        let model = AppModel(client: api, serverURL: account, tokenStorage: storage)
        model.authenticated = true
        await model.refreshWhileActive(true)
        XCTAssertEqual(StubURLProtocol.lastRequest?.value(forHTTPHeaderField: "Authorization"), "Bearer FAKE-TEST-TOKEN")
        let count = StubURLProtocol.requestCount
        await model.logout()
        XCTAssertEqual(deleted, [account]); XCTAssertNil(storage.load(account))
        let authorized = await api.isAuthenticated
        XCTAssertFalse(authorized)
        XCTAssertFalse(model.authenticated); XCTAssertFalse(model.restoring)
        XCTAssertTrue(model.callers.isEmpty); XCTAssertNil(model.broker)
        await model.refreshWhileActive(true)
        await model.refreshAll()
        XCTAssertEqual(StubURLProtocol.requestCount, count, "Sign-out is client-side only; no logout endpoint or signed-out refresh")
        _ = try await api.brokerStatus()
        XCTAssertNil(StubURLProtocol.lastRequest?.value(forHTTPHeaderField: "Authorization"))
    }
    @MainActor func testSignOutDuringRefreshStopsFollowupsAndLatePublication() async {
        PendingTransport.count = 0
        let model = AppModel(client: client(pending: true), serverURL: account,
                             tokenStorage: .init(save: { _, _ in }, load: { _ in nil }, delete: { _ in }))
        model.authenticated = true
        let started = expectation(description: "Broker read held")
        PendingTransport.started = { started.fulfill() }
        let task = Task { await model.refreshWhileActive(true) }
        await fulfillment(of: [started], timeout: 2)
        await model.logout()
        PendingTransport.pending?.respond(200, #"{"running":true}"#)
        await task.value
        await model.refreshWhileActive(true)
        XCTAssertEqual(PendingTransport.count, 1)
        XCTAssertNil(model.broker); XCTAssertTrue(model.callers.isEmpty)
    }
    override func tearDown() {
        StubURLProtocol.handler = nil; StubURLProtocol.requestCount = 0
        StubURLProtocol.lastRequest = nil
        PendingTransport.pending = nil; PendingTransport.started = nil
    }
}
