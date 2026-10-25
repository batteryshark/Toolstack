import XCTest
@testable import ToolstackKit
@testable import ToolstackApp

final class NativeContractTests: XCTestCase {
    private func client(pending: Bool = false, token: String? = "FAKE") -> ApiClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = pending ? [PendingTransport.self] : [StubURLProtocol.self]
        return ApiClient(baseURL: URL(string: "http://fake.invalid")!, session: URLSession(configuration: config), token: token)
    }
    private let tool = #"{"id":"demo","type":"api","running":true,"alive":true,"removable":true,"path":"/fake/demo"}"#
    override func tearDown() {
        StubURLProtocol.handler = nil; PendingTransport.started = nil; PendingTransport.pending = nil
    }
    func testCatalogAuthenticatedStrictDecodeAndNoAnonymousRequest() async throws {
        var requests = 0
        for json in [#"{"status":"verified","observation_id":"ab12","tool_ids":["demo"]}"#, #"{"status":"verified"}"#, #"{"status":"verified","observation_id":"not hex","tool_ids":["demo"]}"#, #"{"status":"unknown","observation_id":"ab12","tool_ids":["demo"]}"#, "{}"] {
            StubURLProtocol.handler = { request in
                requests += 1
                XCTAssertEqual(request.url?.path, "/api/catalog")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer FAKE")
                return (200, [:], Data(json.utf8))
            }
            let result = try await client().catalogObservation()
            XCTAssertEqual(result.verified, json == #"{"status":"verified","observation_id":"ab12","tool_ids":["demo"]}"#)
        }
        do { _ = try await client(token: nil).catalogObservation(); XCTFail("Anonymous read") }
        catch { XCTAssertEqual(error as? ApiError, .unauthorized) }
        XCTAssertEqual(requests, 5)
    }
    @MainActor func testCatalogNeedsPresentTargetAndFailuresInvalidate() async {
        let model = AppModel(client: client(), serverURL: "http://fake.invalid")
        var catalogStatus = 200
        var catalogBody = #"{"status":"verified","observation_id":"ab12","tool_ids":["demo"]}"#
        StubURLProtocol.handler = { request in
            if request.url?.path == "/api/tools" { return (200, [:], Data("{\"tools\":[\(self.tool)]}".utf8)) }
            return (catalogStatus, [:], Data(catalogBody.utf8))
        }
        await model.refreshCatalog()
        XCTAssertTrue(model.registrationObserved(for: "demo"))
        XCTAssertFalse(model.registrationObserved(for: "absent"))
        catalogStatus = 404
        await model.refreshCatalog()
        XCTAssertFalse(model.catalogObservation.verified)
        catalogStatus = 200
        for body in ["not JSON", "{}", #"{"status":"unknown"}"#] {
            catalogBody = body
            await model.refreshCatalog()
            XCTAssertFalse(model.catalogObservation.verified)
        }
        catalogBody = #"{"status":"verified","observation_id":"ab12","tool_ids":["demo"]}"#
        await model.refreshCatalog()
        _ = await model.refreshTools()
        XCTAssertFalse(model.catalogObservation.verified)
    }
    @MainActor func testRegistrationRequiresMembershipInSameCatalogSnapshot() async {
        let model = AppModel(client: client(), serverURL: "http://fake.invalid")
        var catalogBody = "{}"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.httpMethod, "GET")
            if request.url?.path == "/api/tools" {
                // Discovery can outlive the registry snapshot; this tool has zero operations.
                return (200, [:], Data(#"{"tools":[{"id":"A","ops":[]}]}"#.utf8))
            }
            XCTAssertEqual(request.url?.path, "/api/catalog")
            return (200, [:], Data(catalogBody.utf8))
        }
        for ids in ["[]", "[\"B\"]", "[\"A\"]"] {
            catalogBody = "{\"status\":\"verified\",\"observation_id\":\"ab12\",\"tool_ids\":\(ids)}"
            await model.refreshCatalog()
            XCTAssertTrue(model.tools.contains { $0.id == "A" })
            XCTAssertTrue(model.catalogObservation.verified)
            XCTAssertEqual(model.registrationObserved(for: "A"), ids == "[\"A\"]")
            XCTAssertFalse(model.registrationObserved(for: "B"))
        }
        for suffix in ["", ",\"tool_ids\":null", ",\"tool_ids\":\"A\"", ",\"tool_ids\":[\"A\",1]", ",\"tool_ids\":{}"] {
            catalogBody = "{\"status\":\"verified\",\"observation_id\":\"ab12\"\(suffix)}"
            await model.refreshCatalog()
            XCTAssertEqual(model.catalogObservation, .unknown)
            XCTAssertFalse(model.registrationObserved(for: "A"))
        }
    }
    @MainActor func testNamedOwnershipConfirmationsAndReceipts() async throws {
        let unknown = AppModel(client: client(), serverURL: "http://fake.invalid")
        unknown.requestRemoval(try JSONDecoder().decode(ToolInfo.self, from: Data(#"{"id":"unknown"}"#.utf8)))
        XCTAssertNil(unknown.confirmation)
        for external in [true, false] {
            let model = AppModel(client: client(), serverURL: "http://fake.invalid")
            let row = try JSONDecoder().decode(ToolInfo.self, from: Data("{\"id\":\"demo\",\"removable\":\(external),\"path\":\"/fake/demo\"}".utf8))
            model.requestRemoval(row)
            XCTAssertEqual(model.confirmation?.title, external ? "Unregister demo?" : "Remove demo?")
            XCTAssertTrue(model.confirmation?.effect.contains(external ? "retained" : "deletes") == true)
            StubURLProtocol.handler = { request in
                if request.httpMethod == "DELETE" { return (200, [:], Data("{\"removed\":\"demo\",\"deleted\":\(!external)}".utf8)) }
                return (200, [:], Data("{\"tools\":[\(self.tool)]}".utf8))
            }
            await model.confirmation?.action()
            XCTAssertTrue(model.banner?.contains(external ? "files retained" : "managed folder") == true)
            if external { XCTAssertTrue(model.banner?.contains("Other sources") == true) }
        }
    }
    @MainActor func testUnknownDeleteReceiptsAnd500NeverReplayBeforeComparison() async {
        for (status, json) in [(200, #"{"removed":"demo"}"#), (200, "garbled"), (500, #"{"detail":"after effect"}"#)] {
            var deletes = 0
            StubURLProtocol.handler = { request in
                if request.httpMethod == "DELETE" { deletes += 1; return (status, [:], Data(json.utf8)) }
                if request.url?.path == "/api/broker" { return (200, [:], Data(#"{"running":true}"#.utf8)) }
                return (200, [:], Data(#"{"tools":[]}"#.utf8))
            }
            let model = AppModel(client: client(), serverURL: "http://fake.invalid")
            await model.removeTool(id: "demo")
            XCTAssertTrue(model.uncertainMutation?.contains("demo") == true)
            await model.removeTool(id: "demo")
            XCTAssertEqual(deletes, 1)
            await model.compareMutationState()
            XCTAssertNil(model.uncertainMutation)
            XCTAssertTrue(model.banner?.contains("Filesystem outcome remains unknown") == true)
            XCTAssertEqual(deletes, 1)
        }
    }
    @MainActor func testLegacyUnsupportedRemovalIsRejected() async {
        StubURLProtocol.handler = { _ in (400, [:], Data(#"{"detail":"external unsupported"}"#.utf8)) }
        let model = AppModel(client: client(), serverURL: "http://fake.invalid")
        await model.removeTool(id: "demo")
        XCTAssertTrue(model.error?.contains("rejected") == true)
        XCTAssertNil(model.banner)
    }
    @MainActor func testComparisonClearsListingErrorWithoutMutationReplay() async {
        var requests: [String] = []
        var listingWorks = false
        StubURLProtocol.handler = { request in
            let path = request.url!.path
            requests.append("\(request.httpMethod!) \(path)")
            if path == "/api/broker" { return (200, [:], Data(#"{"running":true}"#.utf8)) }
            if request.httpMethod == "POST" { return (200, [:], Data(self.tool.utf8)) }
            return (listingWorks ? 200 : 500, [:], Data(#"{"tools":[{"id":"fresh"}]}"#.utf8))
        }
        let model = AppModel(client: client(), serverURL: "http://fake.invalid")
        _ = await model.refreshTools()
        XCTAssertNotNil(model.toolsError)
        await model.toolAction(id: "demo", action: "start", confirmed: true)
        XCTAssertNotNil(model.uncertainMutation)
        XCTAssertNotNil(model.toolsError)
        listingWorks = true
        await model.compareMutationState()
        XCTAssertNil(model.toolsError)
        XCTAssertNil(model.uncertainMutation)
        XCTAssertEqual(model.tools.map(\.id), ["fresh"])
        XCTAssertEqual(model.broker?.running, true)
        XCTAssertFalse(model.catalogObservation.verified)
        XCTAssertFalse(model.registrationObserved(for: "fresh"))
        XCTAssertFalse(model.effectInFlight)
        XCTAssertEqual(requests, ["GET /api/tools", "POST /api/tools/demo/start", "GET /api/tools", "GET /api/broker", "GET /api/tools"])
    }
    @MainActor func testAddStartRestartAreSeparateAndOnlyCatalogVerifies() async {
        var effects: [String] = []
        var alive = false
        StubURLProtocol.handler = { request in
            let path = request.url!.path
            if request.httpMethod == "POST" { effects.append(path) }
            if path == "/api/tools", request.httpMethod == "POST" { return (200, [:], Data(#"{"id":"demo","type":"api","description":"","path":"/fake/demo"}"#.utf8)) }
            if path == "/api/tools/demo/start" { alive = true; return (200, [:], Data(self.tool.utf8)) }
            if path == "/api/tools" { return (200, [:], Data("{\"tools\":[{\"id\":\"demo\",\"running\":\(alive),\"alive\":\(alive)}]}".utf8)) }
            if path == "/api/catalog" { return (200, [:], Data(#"{"status":"verified","observation_id":"ab12","tool_ids":["demo"]}"#.utf8)) }
            return (200, [:], Data(#"{"running":true}"#.utf8))
        }
        let model = AppModel(client: client(), serverURL: "http://fake.invalid")
        _ = await model.addTool(source: "/fake/demo")
        XCTAssertEqual(model.continuationTarget, "demo")
        XCTAssertEqual(effects, ["/api/tools"])
        XCTAssertFalse(model.registrationObserved(for: "demo"))
        await model.toolAction(id: "demo", action: "start")
        XCTAssertEqual(effects.count, 1)
        XCTAssertEqual(model.confirmation?.title, "Start demo?")
        XCTAssertTrue(model.confirmation?.effect.contains("this host's credentials") == true)
        await model.confirmation?.action()
        XCTAssertEqual(effects.count, 2)
        XCTAssertFalse(model.registrationObserved(for: "demo"))
        await model.brokerAction("restart")
        XCTAssertEqual(effects.count, 2)
        await model.confirmation?.action()
        XCTAssertEqual(effects, ["/api/tools", "/api/tools/demo/start", "/api/broker/restart"])
        XCTAssertTrue(model.registrationObserved(for: "demo"))
    }
    @MainActor func testLateCatalogAndDeleteDoNotTouchNewIdentity() async throws {
        for catalog in [true, false] {
            PendingTransport.count = 0
            let first = expectation(description: "first pending")
            let second = expectation(description: "catalog pending")
            PendingTransport.started = {
                if PendingTransport.count == 1 { first.fulfill() }
                else if PendingTransport.count == 2 { second.fulfill() }
                else { PendingTransport.pending?.respond(500, "{}") }
            }
            let model = AppModel(client: client(pending: true), serverURL: "http://fake.invalid")
            let task = Task { if catalog { await model.refreshCatalog() } else { await model.removeTool(id: "demo") } }
            await fulfillment(of: [first], timeout: 2)
            if catalog {
                PendingTransport.pending?.respond(200, "{\"tools\":[\(tool)]}")
                await fulfillment(of: [second], timeout: 2)
            } else {
                second.fulfill()
                await fulfillment(of: [second], timeout: 2)
            }
            model.clearAdminState(); model.banner = "B"
            PendingTransport.pending?.respond(200, catalog ? #"{"status":"verified","observation_id":"ab12","tool_ids":["demo"]}"# : #"{"removed":"demo","deleted":false}"#)
            await task.value
            XCTAssertEqual(model.banner, "B")
            XCTAssertFalse(model.catalogObservation.verified)
            XCTAssertTrue(model.tools.isEmpty)
            XCTAssertNil(model.uncertainMutation)
        }
    }
}
