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

    func testListToolsDecodesOps() async throws {
        let json = #"{"tools":[{"id":"echo","type":"rest","port":4601,"running":false,"#
                 + #""ops":[{"op":"say","risk":"low","description":"echo it"}]}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let tools = try await makeClient(token: "t").listTools()
        XCTAssertEqual(tools.first?.id, "echo")
        XCTAssertEqual(tools.first?.ops.first?.op, "say")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/tools")
    }

    func testListToolsToleratesMissingOps() async throws {
        // an admin that doesn't report `ops` (older version) must not break the whole response
        let json = #"{"tools":[{"id":"echo","type":"rest","port":4601,"path":"x","running":false,"#
                 + #""alive":false,"backend":null,"removable":false}]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let tools = try await makeClient(token: "t").listTools()
        XCTAssertEqual(tools.first?.id, "echo")
        XCTAssertEqual(tools.first?.ops, [])   // defaulted to empty, not a decode failure
    }

    func testGetPolicyDecodes() async throws {
        let json = #"{"name":"hermes","policy":{"tools":{"echo":{"say":"allow"}}},"enabled":["echo"]}"#
        StubURLProtocol.handler = { _ in (200, [:], Data(json.utf8)) }
        let resp = try await makeClient(token: "t").policy(for: "hermes")
        XCTAssertEqual(resp.policy.tools["echo"]?["say"], "allow")
        XCTAssertEqual(resp.policy.effect(tool: "echo", op: "say"), .allow)
        XCTAssertEqual(resp.policy.effect(tool: "echo", op: "shout"), .deny)  // absent -> deny
    }

    func testSetPolicySendsAllowReviewViaPut() async throws {
        StubURLProtocol.handler = { _ in
            (200, [:], Data(#"{"name":"hermes","policy":{"tools":{}},"enabled":[]}"#.utf8))
        }
        _ = try await makeClient(token: "t").setPolicy(caller: "hermes", allow: ["echo.say"], review: [])
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "PUT")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/api/callers/hermes/policy")
        XCTAssertEqual(try bodyJSON()["allow"] as? [String], ["echo.say"])
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
        XCTAssertEqual(resp.tokens.first?.tokenHash, "abcd")  // token_hash -> tokenHash
    }
}
