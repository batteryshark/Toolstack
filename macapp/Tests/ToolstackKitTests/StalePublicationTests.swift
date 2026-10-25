import XCTest
@testable import ToolstackKit
@testable import ToolstackApp

extension PendingTransport {
    func respond(_ status: Int, _ json: String) {
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(json.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
}

final class StalePublicationTests: XCTestCase {
    @MainActor func testLateCombinedSettingsCannotCrossAnAccountReset() async throws {
        let model = model()
        let json = #"{"name":"A","caller_id":1,"operator":"admin","installation":"fake","revision":"one","enabled":["echo"],"policy":{"tools":{"echo":{"say":"review"}}},"catalog":{"echo":[{"op":"say","risk":"read","description":"fake"}]}}"#
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        var draft = CallerSettingsDraft(try decoder.decode(SettingsSnapshot.self, from: Data(json.utf8)))
        draft.values.tools["echo"]?["say"] = "allow"
        let started = expectation(description: "combined settings pending")
        PendingTransport.started = { if PendingTransport.count == 1 { started.fulfill() } }
        let pending = draft
        let task = Task { await model.writeCallerSettings(pending) }
        await fulfillment(of: [started], timeout: 2)
        try seedB(model)
        PendingTransport.pending?.respond(200, #"{"outcome":"saved","name":"A","policy":{"enabled":["echo"],"tools":{"echo":{"say":"allow"}},"disabled_functions":{"echo":[]}}}"#)
        let returned = await task.value
        XCTAssertEqual(returned, pending, "A late receipt is not consumable as a saved B draft")
        assertB(model)
    }

    @MainActor private func model() -> AppModel {
        PendingTransport.count = 0
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [PendingTransport.self]
        return AppModel(client: ApiClient(baseURL: URL(string: "http://admin-a.invalid")!, session: URLSession(configuration: configuration)), serverURL: "http://admin-a.invalid")
    }
    @MainActor private func seedB(_ model: AppModel) throws {
        model.clearAdminState()
        model.serverURL = "http://admin-b.invalid"
        model.authenticated = true
        model.banner = "B banner"; model.error = "B error"; model.busy = true
        model.callers = try JSONDecoder().decode(CallersResponse.self, from: Data(#"{"callers":[{"id":2,"name":"B"}]}"#.utf8)).callers
        model.broker = BrokerStatus(running: false, port: 2222)
        model.tools = try JSONDecoder().decode(ToolsResponse.self, from: Data(#"{"tools":[{"id":"B-tool"}]}"#.utf8)).tools
        model.policyDrafts["B"] = PolicyDraft(caller: "B")
    }
    @MainActor private func assertB(_ model: AppModel) {
        XCTAssertTrue(model.authenticated); XCTAssertTrue(model.busy)
        XCTAssertEqual(model.banner, "B banner"); XCTAssertEqual(model.error, "B error")
        XCTAssertEqual(model.callers.map(\.name), ["B"])
        XCTAssertEqual(model.tools.map(\.id), ["B-tool"])
        XCTAssertEqual(model.broker?.port, 2222)
        XCTAssertEqual(Set(model.policyDrafts.keys), ["B"])
        XCTAssertNil(model.audit); XCTAssertNil(model.config); XCTAssertNil(model.secretBackend)
        XCTAssertEqual(PendingTransport.count, 1, "Old task must not start follow-up requests")
    }
    @MainActor func testDelayedReadsDoNotPublishIntoResetIdentity() async throws {
        let cases: [(String, (AppModel) async -> Void)] = [
            (#"{"callers":[{"id":1,"name":"A"}]}"#, { await $0.refreshCallers() }),
            (#"{"running":true,"port":1111}"#, { await $0.refreshBroker() }),
            (#"{"audit":[],"requests":[]}"#, { await $0.refreshAudit() }),
            (#"{"plugin":"A"}"#, { await $0.refreshSecretBackend() }),
            (#"{"port":1111,"toolsRoot":"/fake","nodUrl":"fake","nodToken":"not set","nodChannel":"fake","approvalTtl":1,"rateLimit":1}"#, { await $0.refreshConfig() }),
            (#"{"tools":[{"id":"A-tool"}]}"#, { _ = await $0.refreshTools() })
        ]
        for (json, operation) in cases {
            let model = model()
            let started = expectation(description: "A read pending")
            PendingTransport.started = { if PendingTransport.count == 1 { started.fulfill() } else { PendingTransport.pending?.respond(500, "{}") } }
            let task = Task { await operation(model) }
            await fulfillment(of: [started], timeout: 2)
            try seedB(model)
            PendingTransport.pending?.respond(200, json)
            await task.value
            assertB(model)
        }
    }
    @MainActor func testLateCreateAndRotateReceiptsNeverPublishTokenOrRefresh() async throws {
        for rotate in [false, true] {
            let model = model()
            let started = expectation(description: "A mutation pending")
            PendingTransport.started = { if PendingTransport.count == 1 { started.fulfill() } else { PendingTransport.pending?.respond(500, "{}") } }
            let task = Task {
                if rotate { await model.rotateToken(caller: "A", confirmed: true) }
                else { await model.createCaller(name: "A") }
            }
            await fulfillment(of: [started], timeout: 2)
            try seedB(model)
            PendingTransport.pending?.respond(200, #"{"name":"A","token":"FAKE-ONE-TIME-A"}"#)
            await task.value
            assertB(model)
        }
    }
    @MainActor func testLateUnauthorizedDoesNotSignOutB() async throws {
        let model = model()
        let started = expectation(description: "A pending")
        PendingTransport.started = { if PendingTransport.count == 1 { started.fulfill() } else { PendingTransport.pending?.respond(500, "{}") } }
        let task = Task { await model.refreshCallers() }
        await fulfillment(of: [started], timeout: 2)
        try seedB(model)
        PendingTransport.pending?.respond(401, #"{"detail":"expired A"}"#)
        await task.value
        assertB(model)
    }
    @MainActor func testLatePolicyReadReturnsNoConsumableValue() async throws {
        let model = model()
        let started = expectation(description: "A policy pending")
        PendingTransport.started = { if PendingTransport.count == 1 { started.fulfill() } else { PendingTransport.pending?.respond(500, "{}") } }
        let task = Task { await model.loadPolicy(for: "A") }
        await fulfillment(of: [started], timeout: 2)
        try seedB(model)
        PendingTransport.pending?.respond(200, #"{"name":"A","enabled":[],"policy":{"tools":{}}}"#)
        let result = await task.value
        XCTAssertNil(result)
        assertB(model)
    }
    @MainActor func testLateToolAndConfigAcknowledgementsDoNotPublishOrFollowUp() async throws {
        let created = #"{"id":"A","type":"api","description":"A","path":"/fake/A"}"#
        let cases: [(String, (AppModel) async -> Void)] = [
            (created, { _ = await $0.addTool(source: "/fake/A") }),
            (created, { _ = await $0.authorTool(source: "/fake/A", manifest: [:]) }),
            (created, { await $0.addToolFromGitHub(repo: "fake", subdir: "", ref: "") }),
            (created, { await $0.resyncTool(id: "A") }),
            (#"{"id":"A","description":"A","secrets":[]}"#, { await $0.updateTool(id: "A", description: "A", secrets: []) }),
            (#"{"removed":"A"}"#, { await $0.removeTool(id: "A") }),
            (#"{"port":1111,"toolsRoot":"/fake","nodUrl":"fake","nodToken":"not set","nodChannel":"fake","approvalTtl":1,"rateLimit":1}"#, { await $0.saveConfig(port: 1111, toolsRoot: "/fake", nodURL: "fake", nodChannel: "fake", nodToken: nil, approvalTTL: 1, rateLimit: 1) })
        ]
        for (json, operation) in cases {
            let model = model()
            let started = expectation(description: "A effect pending")
            PendingTransport.started = { if PendingTransport.count == 1 { started.fulfill() } else { PendingTransport.pending?.respond(500, "{}") } }
            let task = Task { await operation(model) }
            await fulfillment(of: [started], timeout: 2)
            try seedB(model)
            PendingTransport.pending?.respond(200, json)
            await task.value
            assertB(model)
        }
    }
    @MainActor func testLateRestoreProofDoesNotReplaceBSession() async throws {
        let model = model()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [PendingTransport.self]
        let restored = ApiClient(baseURL: URL(string: "http://admin-a.invalid")!, session: URLSession(configuration: configuration))
        let started = expectation(description: "A restore proof pending")
        PendingTransport.started = { if PendingTransport.count == 1 { started.fulfill() } else { PendingTransport.pending?.respond(500, "{}") } }
        let task = Task { try await model.acceptRestoredSession(restored, account: "http://admin-a.invalid") }
        await fulfillment(of: [started], timeout: 2)
        try seedB(model)
        PendingTransport.pending?.respond(200, #"{"running":true,"port":1111}"#)
        try await task.value
        assertB(model)
    }
    @MainActor func testLatePolicyWriteCannotRepopulateDrafts() async throws {
        let model = model()
        let receipt = #"{"name":"A","enabled":[],"policy":{"tools":{}}}"#
        var draft = PolicyDraft(caller: "A")
        draft.load(try JSONDecoder().decode(PolicyResponse.self, from: Data(receipt.utf8)))
        let started = expectation(description: "A policy write pending")
        PendingTransport.started = { if PendingTransport.count == 1 { started.fulfill() } else { PendingTransport.pending?.respond(500, "{}") } }
        let epoch = model.generation
        let task = Task { await model.writePolicy(draft) }
        await fulfillment(of: [started], timeout: 2)
        try seedB(model)
        PendingTransport.pending?.respond(200, receipt)
        _ = await task.value
        XCTAssertNotEqual(epoch, model.generation, "Old editor continuation must ignore its returned draft")
        assertB(model)
    }
    @MainActor func testPreActionRefreshCannotOverwriteAcknowledgedActionListing() async throws {
        for staleStatus in [200, 500] {
            let model = model()
            let first = expectation(description: "old refresh")
            let action = expectation(description: "action")
            let listing = expectation(description: "post-action listing")
            PendingTransport.started = {
                switch PendingTransport.count {
                case 1: first.fulfill()
                case 2: action.fulfill()
                case 3: listing.fulfill()
                default: XCTFail("Unexpected request"); PendingTransport.pending?.respond(500, "{}")
                }
            }
            let epoch = model.generation
            let oldTask = Task { await model.refreshTools() }
            await fulfillment(of: [first], timeout: 2)
            let old = try XCTUnwrap(PendingTransport.pending)
            let actionTask = Task { await model.toolAction(id: "demo", action: "start", confirmed: true) }
            await fulfillment(of: [action], timeout: 2)
            PendingTransport.pending?.respond(200, #"{"id":"demo"}"#)
            await fulfillment(of: [listing], timeout: 2)
            PendingTransport.pending?.respond(200, #"{"tools":[{"id":"fresh"}]}"#)
            await actionTask.value
            old.respond(staleStatus, #"{"tools":[{"id":"stale"}]}"#)
            let accepted = await oldTask.value
            XCTAssertFalse(accepted)
            XCTAssertEqual(model.tools.map(\.id), ["fresh"])
            XCTAssertNil(model.toolsError)
            XCTAssertEqual(model.generation, epoch)
            XCTAssertFalse(model.effectInFlight)
            XCTAssertEqual(PendingTransport.count, 3)
        }
    }
    @MainActor func testStaleRefreshCannotClearNewerListingError() async throws {
        let model = model()
        let first = expectation(description: "old refresh")
        let second = expectation(description: "new refresh")
        PendingTransport.started = {
            if PendingTransport.count == 1 { first.fulfill() } else { second.fulfill() }
        }
        let oldTask = Task { await model.refreshTools() }
        await fulfillment(of: [first], timeout: 2)
        let old = try XCTUnwrap(PendingTransport.pending)
        let newTask = Task { await model.refreshTools() }
        await fulfillment(of: [second], timeout: 2)
        PendingTransport.pending?.respond(500, "{}")
        _ = await newTask.value
        let freshError = try XCTUnwrap(model.toolsError)
        old.respond(200, #"{"tools":[{"id":"stale"}]}"#)
        _ = await oldTask.value
        XCTAssertEqual(model.toolsError, freshError)
        XCTAssertTrue(model.tools.isEmpty)
        XCTAssertEqual(PendingTransport.count, 2)
    }
    @MainActor func testComparisonCannotClearNewerRevisionErrorOrResetIdentity() async throws {
        for reset in [false, true] {
            let model = model()
            model.uncertainMutation = "start unknown"
            let broker = expectation(description: "comparison broker")
            let list = expectation(description: "comparison list")
            let refresh = expectation(description: "new refresh")
            PendingTransport.started = {
                switch PendingTransport.count {
                case 1: broker.fulfill()
                case 2: list.fulfill()
                case 3: refresh.fulfill()
                default: XCTFail("Unexpected request")
                }
            }
            let comparison = Task { await model.compareMutationState() }
            await fulfillment(of: [broker], timeout: 2)
            PendingTransport.pending?.respond(200, #"{"running":true}"#)
            await fulfillment(of: [list], timeout: 2)
            let old = try XCTUnwrap(PendingTransport.pending)
            if reset { model.clearAdminState(); model.uncertainMutation = "B unknown" }
            let newer = Task { await model.refreshTools() }
            await fulfillment(of: [refresh], timeout: 2)
            PendingTransport.pending?.respond(500, "{}")
            _ = await newer.value
            let freshError = try XCTUnwrap(model.toolsError)
            old.respond(200, #"{"tools":[{"id":"stale"}]}"#)
            await comparison.value
            XCTAssertEqual(model.toolsError, freshError)
            XCTAssertTrue(model.tools.isEmpty)
            XCTAssertNil(model.broker)
            XCTAssertEqual(model.uncertainMutation, reset ? "B unknown" : "start unknown")
            XCTAssertFalse(model.effectInFlight)
        }
    }
    override func tearDown() { PendingTransport.pending = nil; PendingTransport.started = nil }
}
