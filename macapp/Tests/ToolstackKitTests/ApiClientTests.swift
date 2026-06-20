import XCTest
@testable import ToolstackKit

/// A stub URLProtocol: captures the outgoing request (incl. body) and returns a canned
/// (status, headers, data). Lets us drive ApiClient with no real admin / network.
final class StubURLProtocol: URLProtocol {
    static var handler: ((URLRequest) -> (Int, [String: String], Data))?
    static var lastRequest: URLRequest?
    static var lastBody: Data?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        StubURLProtocol.lastRequest = request
        StubURLProtocol.lastBody = Self.readBody(request)
        let (status, headers, data) = StubURLProtocol.handler!(request)
        let resp = HTTPURLResponse(url: request.url!, statusCode: status,
                                   httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    // URLSession moves httpBody to a stream by the time the protocol sees it.
    private static func readBody(_ request: URLRequest) -> Data? {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open(); defer { stream.close() }
        var data = Data()
        let size = 4096
        var buffer = [UInt8](repeating: 0, count: size)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: size)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}

final class ApiClientTests: XCTestCase {
    private func makeClient(token: String? = nil) -> ApiClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        return ApiClient(baseURL: URL(string: "http://test.local")!,
                         session: URLSession(configuration: config), token: token)
    }

    private func bodyJSON() throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(StubURLProtocol.lastBody)) as? [String: Any])
    }

    override func tearDown() {
        StubURLProtocol.handler = nil
        StubURLProtocol.lastRequest = nil
        StubURLProtocol.lastBody = nil
    }

    func testLoginSendsPasswordUnauthedAndStoresToken() async throws {
        StubURLProtocol.handler = { _ in (200, [:], Data(#"{"token":"T123","username":"admin"}"#.utf8)) }
        let client = makeClient()
        let token = try await client.login(password: "pw")
        XCTAssertEqual(token, "T123")
        let authed = await client.isAuthenticated
        XCTAssertTrue(authed)
        let req = try XCTUnwrap(StubURLProtocol.lastRequest)
        XCTAssertEqual(req.httpMethod, "POST")
        XCTAssertEqual(req.url?.path, "/api/login")
        XCTAssertNil(req.value(forHTTPHeaderField: "Authorization"))  // login is not authed
        XCTAssertEqual(try bodyJSON()["password"] as? String, "pw")
    }

    func testAuthedRequestSendsBearer() async throws {
        StubURLProtocol.handler = { _ in
            (200, [:], Data(#"{"running":false,"pid":null,"port":null,"healthy":null}"#.utf8))
        }
        let client = makeClient(token: "TOK")
        let status = try await client.brokerStatus()
        XCTAssertFalse(status.running)
        XCTAssertEqual(StubURLProtocol.lastRequest?.value(forHTTPHeaderField: "Authorization"), "Bearer TOK")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/broker")
    }

    func testUnauthorizedMapsToApiError() async {
        StubURLProtocol.handler = { _ in (401, [:], Data(#"{"detail":"unauthorized"}"#.utf8)) }
        let client = makeClient(token: "bad")
        do {
            _ = try await client.brokerStatus()
            XCTFail("expected unauthorized to throw")
        } catch {
            XCTAssertEqual(error as? ApiError, .unauthorized)
        }
    }

    func testHttpErrorCarriesServerDetail() async {
        StubURLProtocol.handler = { _ in (502, [:], Data(#"{"detail":"broker start failed: boom"}"#.utf8)) }
        let client = makeClient(token: "t")
        do {
            _ = try await client.brokerAction("start")
            XCTFail("expected 502 to throw")
        } catch {
            guard case .http(let status, let message)? = error as? ApiError else {
                return XCTFail("wrong error: \(error)")
            }
            XCTAssertEqual(status, 502)
            XCTAssertTrue(message.contains("boom"), message)
        }
    }

    func testCreateCallerSendsBodyAndParsesToken() async throws {
        StubURLProtocol.handler = { _ in (200, [:], Data(#"{"name":"hermes","token":"NEWTOK"}"#.utf8)) }
        let client = makeClient(token: "t")
        let created = try await client.createCaller(name: "hermes", allow: ["echo.say"])
        XCTAssertEqual(created.token, "NEWTOK")
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "POST")
        let body = try bodyJSON()
        XCTAssertEqual(body["name"] as? String, "hermes")
        XCTAssertEqual(body["allow"] as? [String], ["echo.say"])
    }

    func testRotateTokenPostsAndReturnsNewToken() async throws {
        StubURLProtocol.handler = { _ in (200, [:], Data(#"{"name":"hermes","token":"ROT123"}"#.utf8)) }
        let created = try await makeClient(token: "t").rotateToken(caller: "hermes")
        XCTAssertEqual(created.token, "ROT123")
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/callers/hermes/rotate-token")
    }

    func testRevokeCallerPosts() async throws {
        StubURLProtocol.handler = { _ in (200, [:], Data(#"{"name":"hermes"}"#.utf8)) }
        let result = try await makeClient(token: "t").revokeCaller("hermes")
        XCTAssertEqual(result.name, "hermes")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/callers/hermes/revoke")
    }

    func testConfigDecodesMasked() async throws {
        let json = #"{"port":8765,"db_path":"/x","tools_root":"tools","nod_url":"https://n/boop","#
                 + #""nod_token":"set","nod_channel":"ops","approval_ttl":3600,"rate_limit":120,"tool_dirs":[]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let cfg = try await makeClient(token: "t").config()
        XCTAssertEqual(cfg.nodChannel, "ops")
        XCTAssertEqual(cfg.approvalTtl, 3600)
        XCTAssertTrue(cfg.nodTokenSet)  // "set" -> true
    }

    func testSaveConfigSendsTokenOnlyWhenProvided() async throws {
        let json = #"{"port":8765,"tools_root":"tools","nod_url":"","nod_token":"not set","#
                 + #""nod_channel":"","approval_ttl":3600,"rate_limit":120}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let client = makeClient(token: "t")
        // no token -> body omits nod_token (so the stored one is kept)
        _ = try await client.saveConfig(port: 8765, toolsRoot: "tools", nodURL: "", nodChannel: "",
                                        nodToken: nil, approvalTTL: 3600, rateLimit: 120)
        XCTAssertNil(try bodyJSON()["nod_token"])
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "POST")
        // a token -> included
        _ = try await client.saveConfig(port: 8765, toolsRoot: "tools", nodURL: "", nodChannel: "",
                                        nodToken: "tok", approvalTTL: 3600, rateLimit: 120)
        XCTAssertEqual(try bodyJSON()["nod_token"] as? String, "tok")
    }

    func testSetEnabledToolsPutsList() async throws {
        StubURLProtocol.handler = { _ in (200, [:], Data(#"{"name":"hermes","enabled":["echo"]}"#.utf8)) }
        let enabled = try await makeClient(token: "t").setEnabledTools(caller: "hermes", enabled: ["echo"])
        XCTAssertEqual(enabled, ["echo"])
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "PUT")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/callers/hermes/tools")
        XCTAssertEqual(try bodyJSON()["enabled"] as? [String], ["echo"])
    }

    func testToolActionPostsToActionPath() async throws {
        StubURLProtocol.handler = { _ in
            (200, [:], Data(#"{"id":"echo","type":"api","running":true,"ops":[],"secrets":[]}"#.utf8))
        }
        let tool = try await makeClient(token: "t").toolAction(id: "echo", action: "restart")
        XCTAssertTrue(tool.running)
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools/echo/restart")
    }

    func testDeleteToolSendsDELETE() async throws {
        StubURLProtocol.handler = { _ in (200, [:], Data(#"{"removed":"echo"}"#.utf8)) }
        let removed = try await makeClient(token: "t").deleteTool(id: "echo")
        XCTAssertEqual(removed, "echo")
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "DELETE")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools/echo")
    }

    func testListToolsDecodesOps() async throws {
        let json = #"{"tools":[{"id":"echo","type":"api","port":4601,"running":false,"#
                 + #""ops":[{"op":"say","risk":"low","description":"echo it"}]}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let tools = try await makeClient(token: "t").listTools()
        XCTAssertEqual(tools.first?.id, "echo")
        XCTAssertEqual(tools.first?.ops.first?.op, "say")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools")
    }

    func testListToolsToleratesMissingOps() async throws {
        // an admin that doesn't report `ops` (older version) must not break the whole response
        let json = #"{"tools":[{"id":"echo","type":"api","port":4601,"path":"x","running":false,"#
                 + #""alive":false,"backend":null,"removable":false}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let tools = try await makeClient(token: "t").listTools()
        XCTAssertEqual(tools.first?.id, "echo")
        XCTAssertEqual(tools.first?.ops, [])   // defaulted to empty, not a decode failure
    }

    func testListToolsDecodesSecrets() async throws {
        let json = #"{"tools":[{"id":"echo","type":"api","port":4601,"running":false,"ops":[],"#
                 + #""secrets":[{"name":"api_key","field":"API_KEY","writable":true,"vault":null,"item":null}]}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let tools = try await makeClient(token: "t").listTools()
        XCTAssertEqual(tools.first?.secrets.first?.name, "api_key")
        XCTAssertTrue(try XCTUnwrap(tools.first?.secrets.first).writable)
    }

    func testSecretBackendDecodes() async throws {
        StubURLProtocol.handler = { _ in (200, [:], Data(#"{"name":"vault","path":"/data/vault.json"}"#.utf8)) }
        let backend = try await makeClient(token: "t").secretBackend()
        XCTAssertEqual(backend.name, "vault")
        XCTAssertEqual(backend.path, "/data/vault.json")
    }

    func testAddToolPostsSource() async throws {
        let json = #"{"id":"weather","type":"api","description":"wx","path":"/data/tools/weather"}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let created = try await makeClient(token: "t").addTool(source: "/src/weather")
        XCTAssertEqual(created.id, "weather")
        XCTAssertEqual(created.path, "/data/tools/weather")
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools")
        XCTAssertEqual(try bodyJSON()["source"] as? String, "/src/weather")
    }

    func testAddToolFromGitHubPostsRepoSubdirRef() async throws {
        let json = #"{"id":"gh","type":"api","description":"","path":"/data/tools/gh"}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let created = try await makeClient(token: "t").addToolFromGitHub(
            repo: "https://github.com/x/y", subdir: "tools/a", ref: "main")
        XCTAssertEqual(created.id, "gh")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools")
        let body = try bodyJSON()
        XCTAssertEqual(body["repo"] as? String, "https://github.com/x/y")
        XCTAssertEqual(body["subdir"] as? String, "tools/a")
        XCTAssertEqual(body["ref"] as? String, "main")
    }

    func testAddToolFromGitHubOmitsEmptyOptionals() async throws {
        StubURLProtocol.handler = { _ in
            (200, [:], Data(#"{"id":"gh","type":"api","description":"","path":"/p"}"#.utf8))
        }
        _ = try await makeClient(token: "t").addToolFromGitHub(repo: "https://github.com/x/y")
        let body = try bodyJSON()
        XCTAssertEqual(body["repo"] as? String, "https://github.com/x/y")
        XCTAssertNil(body["subdir"])   // empty optionals omitted, so the server uses its defaults
        XCTAssertNil(body["ref"])
    }

    func testAuthorToolPostsSourceAndManifest() async throws {
        StubURLProtocol.handler = { _ in
            (200, [:], Data(#"{"id":"authored","type":"api","description":"","path":"/p"}"#.utf8))
        }
        let manifest: [String: Any] = ["id": "authored", "type": "api", "command": "python3 app.py",
                                       "port": 4800, "operations": [["name": "go", "risk": "low"]]]
        let created = try await makeClient(token: "t").addToolWithManifest(source: "/code", manifest: manifest)
        XCTAssertEqual(created.id, "authored")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools")
        let body = try bodyJSON()
        XCTAssertEqual(body["source"] as? String, "/code")
        let sent = try XCTUnwrap(body["manifest"] as? [String: Any])
        XCTAssertEqual(sent["id"] as? String, "authored")
        XCTAssertEqual((sent["operations"] as? [[String: Any]])?.first?["name"] as? String, "go")
    }

    func testAddToolNoManifestMapsTo422() async throws {
        StubURLProtocol.handler = { _ in
            (422, [:], Data(#"{"detail":"folder has no toolyard.toml — author one to add it"}"#.utf8))
        }
        do {
            _ = try await makeClient(token: "t").addTool(source: "/src/codeonly")
            XCTFail("expected an error")
        } catch ApiError.http(let status, _) {
            XCTAssertEqual(status, 422)   // the app special-cases this to offer authoring
        }
    }

    func testSecretStatusDecodes() async throws {
        let json = #"{"backend":"vault","settable":true,"fields":["API_KEY"],"provisioned":["API_KEY"]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let s = try await makeClient(token: "t").secretStatus(toolId: "echo")
        XCTAssertTrue(s.settable)
        XCTAssertEqual(s.provisioned, ["API_KEY"])
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "GET")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools/echo/secrets")
    }

    func testSetSecretValuePostsFieldAndValue() async throws {
        StubURLProtocol.handler = { _ in (200, [:], Data(#"{"field":"API_KEY","set":true}"#.utf8)) }
        let ok = try await makeClient(token: "t").setSecretValue(toolId: "echo", field: "API_KEY", value: "s3cr3t")
        XCTAssertTrue(ok)
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools/echo/secrets")
        let body = try bodyJSON()
        XCTAssertEqual(body["field"] as? String, "API_KEY")
        XCTAssertEqual(body["value"] as? String, "s3cr3t")
    }

    func testAuditDecodesEventsRequestsAndDetails() async throws {
        let json = #"{"audit":[{"id":1,"at":1.5,"component":"admin","event_type":"tool_created","#
                 + #""outcome":"ok","correlation_id":"c1","request_id":null,"details":{"tool":"echo","n":2}}],"#
                 + #""requests":[{"id":7,"correlation_id":"c9","caller_id":3,"tool":"echo","op":"say","#
                 + #""status":"completed","error":null,"created_at":2.0,"updated_at":3.0}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let resp = try await makeClient(token: "t").audit(limit: 100)
        XCTAssertEqual(resp.audit.first?.eventType, "tool_created")   // snake_case mapped
        XCTAssertNil(resp.audit.first?.requestId)                     // null → nil
        XCTAssertEqual(resp.audit.first?.details?.compact, "{n: 2, tool: echo}")  // arbitrary JSON rendered
        XCTAssertEqual(resp.requests.first?.callerId, 3)
        XCTAssertEqual(resp.requests.first?.op, "say")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/audit")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.query, "limit=100")   // query support works
    }

    func testResyncToolPostsToUpdatePath() async throws {
        let json = #"{"id":"weather","type":"api","description":"wx","path":"/data/tools/weather"}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let updated = try await makeClient(token: "t").resyncTool(id: "weather")
        XCTAssertEqual(updated.id, "weather")
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools/weather/update")
    }

    func testListToolsDecodesGitHubSource() async throws {
        let json = #"{"tools":[{"id":"gh","type":"api","ops":[],"secrets":[],"#
                 + #""source":{"type":"github","url":"https://github.com/x/y","subdir":"t/a","ref":"main"}}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let tools = try await makeClient(token: "t").listTools()
        XCTAssertEqual(tools.first?.source?.type, "github")
        XCTAssertEqual(tools.first?.source?.url, "https://github.com/x/y")
        XCTAssertEqual(tools.first?.source?.subdir, "t/a")
    }

    func testListToolsToleratesNullSource() async throws {
        // a hand-authored tool has source:null (and an older admin omits it) — both decode to nil
        let json = #"{"tools":[{"id":"echo","type":"api","ops":[],"secrets":[],"source":null}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let tools = try await makeClient(token: "t").listTools()
        XCTAssertNil(tools.first?.source)
    }

    func testListToolsDecodesDescription() async throws {
        let json = #"{"tools":[{"id":"echo","type":"api","description":"echoes input","port":4601,"#
                 + #""running":false,"ops":[],"secrets":[]}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let tools = try await makeClient(token: "t").listTools()
        XCTAssertEqual(tools.first?.description, "echoes input")
    }

    func testUpdateToolPostsDescriptionAndSecrets() async throws {
        let json = #"{"id":"echo","description":"new","secrets":[{"name":"api_key","field":"K","writable":true,"#
                 + #""vault":null,"item":null}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let result = try await makeClient(token: "t").updateTool(
            id: "echo", description: "new",
            secrets: [SecretDecl(name: "api_key", field: "K", writable: true)])
        XCTAssertEqual(result.description, "new")
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools/echo")
        let body = try bodyJSON()
        XCTAssertEqual(body["description"] as? String, "new")
        let secrets = try XCTUnwrap(body["secrets"] as? [[String: Any]])
        XCTAssertEqual(secrets.first?["field"] as? String, "K")
        XCTAssertEqual(secrets.first?["writable"] as? Bool, true)
        // a declaration with no vault/item omits those keys (file backend stays clean)
        XCTAssertNil(secrets.first?["vault"])
    }

    func testGetPolicyDecodes() async throws {
        let json = #"{"name":"hermes","policy":{"tools":{"echo":{"say":"allow"}}},"enabled":["echo"]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let resp = try await makeClient(token: "t").policy(for: "hermes")
        XCTAssertEqual(resp.policy.tools["echo"]?["say"], "allow")
        XCTAssertEqual(resp.policy.effect(tool: "echo", op: "say"), .allow)
        XCTAssertEqual(resp.policy.effect(tool: "echo", op: "shout"), .deny)  // absent -> deny
    }

    func testSetPolicySendsAllowReviewDenyViaPut() async throws {
        StubURLProtocol.handler = { _ in
            (200, [:], Data(#"{"name":"hermes","policy":{"tools":{}},"enabled":[]}"#.utf8))
        }
        // path-scoped specs + an explicit deny carve-out ride through unchanged
        _ = try await makeClient(token: "t").setPolicy(
            caller: "hermes", allow: ["kv.GET /items/**"], review: [], deny: ["kv.GET /items/secret"])
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "PUT")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/callers/hermes/policy")
        XCTAssertEqual(try bodyJSON()["allow"] as? [String], ["kv.GET /items/**"])
        XCTAssertEqual(try bodyJSON()["deny"] as? [String], ["kv.GET /items/secret"])
        // declares itself path-aware so the broker won't refuse an intentional rule removal
        XCTAssertEqual(try bodyJSON()["manages_path_rules"] as? Bool, true)
    }

    func testListCallersDecodesSnakeCase() async throws {
        // `created_at` on the caller is an EXTRA column (list_callers does SELECT *) that the
        // Caller model omits — it must decode anyway (unknown keys ignored), so keep it here.
        let json = #"{"callers":[{"id":1,"name":"hermes","created_at":2.0,"revoked_at":null}],"#
                 + #""tokens":[{"token_hash":"abcd","caller":"hermes","created_at":1.0,"revoked_at":null}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let client = makeClient(token: "t")
        let resp = try await client.listCallers()
        XCTAssertEqual(resp.callers.first?.name, "hermes")
        XCTAssertTrue(try XCTUnwrap(resp.callers.first).isActive)
        // the response's "tokens" key is ignored (unknown keys don't break the decode)
    }
}
