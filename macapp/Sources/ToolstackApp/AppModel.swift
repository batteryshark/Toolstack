import Foundation
import SwiftUI
import ToolstackKit

/// The app's single source of UI state. Wraps the `ApiClient` (an actor) and republishes
/// results on the main actor for SwiftUI. The bearer token lives in the client for the
/// session (Keychain persistence is a T-031 item). Auth errors drop back to the login screen.
@MainActor
final class AppModel: ObservableObject {
    @Published var authenticated = false
    @Published var broker: BrokerStatus?
    @Published var callers: [Caller] = []
    @Published var tokens: [TokenInfo] = []
    @Published var banner: String?   // e.g. a freshly minted token to copy once
    @Published var error: String?
    @Published var busy = false

    private let client: ApiClient

    init(client: ApiClient = ApiClient(baseURL: AppModel.adminURL())) {
        self.client = client
    }

    /// The admin to talk to — `$TOOLSTACK_ADMIN_URL` or the loopback default.
    nonisolated static func adminURL() -> URL {
        if let raw = ProcessInfo.processInfo.environment["TOOLSTACK_ADMIN_URL"],
           let url = URL(string: raw) { return url }
        return URL(string: "http://127.0.0.1:8780")!
    }

    func login(password: String) async {
        await run {
            _ = try await self.client.login(password: password)
            self.authenticated = true
            await self.refreshAll()
        }
    }

    func logout() async {
        await client.setToken(nil)
        authenticated = false
        broker = nil; callers = []; tokens = []; banner = nil
    }

    func refreshAll() async {
        await refreshBroker()
        await refreshCallers()
    }

    func refreshBroker() async {
        await run { self.broker = try await self.client.brokerStatus() }
    }

    func brokerAction(_ action: String) async {
        await run { self.broker = try await self.client.brokerAction(action) }
    }

    func refreshCallers() async {
        await run {
            let response = try await self.client.listCallers()
            self.callers = response.callers
            self.tokens = response.tokens
        }
    }

    func createCaller(name: String) async {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        await run {
            let created = try await self.client.createCaller(name: trimmed)
            self.banner = "Token for \(created.name) — copy it now, it won't be shown again:\n\(created.token)"
            await self.refreshCallers()
        }
    }

    /// Run an async operation with busy/error bookkeeping; an `unauthorized` drops to login.
    private func run(_ operation: @escaping () async throws -> Void) async {
        busy = true
        error = nil
        do {
            try await operation()
        } catch let apiError as ApiError {
            if case .unauthorized = apiError { authenticated = false }
            error = apiError.message
        } catch let other {
            error = other.localizedDescription
        }
        busy = false
    }
}
