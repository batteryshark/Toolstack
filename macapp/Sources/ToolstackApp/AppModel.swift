import Foundation
import SwiftUI
import ToolstackKit

/// The app's single source of UI state. Wraps the `ApiClient` (an actor) and republishes
/// results on the main actor for SwiftUI. The bearer token lives in the client and
/// persists across launches in the Keychain. Auth errors drop back to the login screen.
@MainActor
final class AppModel: ObservableObject {
    @Published var authenticated = false
    @Published var restoring = true   // true until a stored token is checked on launch (avoids a login flash)
    @Published var broker: BrokerStatus?
    @Published var callers: [Caller] = []
    @Published var tools: [ToolInfo] = []
    @Published var banner: String?   // e.g. a freshly minted token to copy once
    @Published var error: String?
    @Published var busy = false

    /// The admin URL the user signs in against — editable on the login screen, remembered
    /// across launches. Works for a local admin (the default) or a remote one (a tailnet /
    /// tunnelled homeserver), as long as it's reachable.
    @Published var serverURL: String
    private var client: ApiClient
    private static let urlDefaultsKey = "ToolstackAdminURL"

    init() {
        let saved = UserDefaults.standard.string(forKey: AppModel.urlDefaultsKey)
        self.serverURL = saved ?? AppModel.adminURL().absoluteString
        self.client = ApiClient(baseURL: AppModel.adminURL())  // rebuilt from serverURL on login
    }

    /// The default admin URL — `$TOOLSTACK_ADMIN_URL` or loopback.
    nonisolated static func adminURL() -> URL {
        if let raw = ProcessInfo.processInfo.environment["TOOLSTACK_ADMIN_URL"],
           let url = URL(string: raw) { return url }
        return URL(string: "http://127.0.0.1:8780")!
    }

    func login(password: String) async {
        let trimmed = serverURL.trimmingCharacters(in: .whitespaces)
        guard let url = URL(string: trimmed), url.scheme != nil, url.host != nil else {
            error = "Enter a valid admin URL — e.g. http://127.0.0.1:8780"
            return
        }
        serverURL = trimmed
        UserDefaults.standard.set(trimmed, forKey: AppModel.urlDefaultsKey)
        client = ApiClient(baseURL: url)   // point at whatever admin the user entered
        await run {
            let token = try await self.client.login(password: password)
            TokenStore.save(token, account: trimmed)   // remember it for next launch
            self.authenticated = true
            await self.refreshAll()
        }
    }

    /// On launch, try a token saved for the current admin URL. Validate it with a lightweight authed
    /// call; enter only on success. A 401 means it expired → forget it; any other error (admin
    /// unreachable) keeps it for next time and just stays on the login screen.
    func restoreSession() async {
        defer { restoring = false }
        let saved = serverURL.trimmingCharacters(in: .whitespaces)
        guard let url = URL(string: saved), url.host != nil,
              let token = TokenStore.load(account: saved) else { return }
        let restored = ApiClient(baseURL: url)
        await restored.setToken(token)
        do {
            _ = try await restored.brokerStatus()   // authed probe
            client = restored
            authenticated = true
            await refreshAll()
        } catch ApiError.unauthorized {
            TokenStore.delete(account: saved)
        } catch {
            // admin unreachable / transient — keep the token, let the user sign in manually
        }
    }

    func logout() async {
        await client.setToken(nil)
        TokenStore.delete(account: serverURL)
        authenticated = false
        broker = nil; callers = []; banner = nil
    }

    func refreshAll() async {
        await refreshBroker()
        await refreshCallers()
        await refreshTools()
    }

    func refreshTools() async {
        await run { self.tools = try await self.client.listTools() }
    }

    /// Start / stop / restart a tool, then refresh so its row reflects the new run state.
    func toolAction(id: String, action: String) async {
        await run {
            _ = try await self.client.toolAction(id: id, action: action)
            await self.refreshTools()
        }
    }

    func updateTool(id: String, description: String, secrets: [SecretDecl]) async {
        await run {
            _ = try await self.client.updateTool(id: id, description: description, secrets: secrets)
            await self.refreshTools()
            self.banner = "Saved \(id). Restart the tool if you changed its secrets."
        }
    }

    /// Re-pull a tool from its recorded source, keeping the operator's description/secret edits.
    func resyncTool(id: String) async {
        await run {
            _ = try await self.client.resyncTool(id: id)
            await self.refreshTools()
            self.banner = "Updated \(id) from its source. Restart the broker if its entrypoint or operations changed."
        }
    }

    func removeTool(id: String) async {
        await run {
            _ = try await self.client.deleteTool(id: id)
            await self.refreshTools()
            self.banner = "Removed \(id). Restart the broker to drop it from the registry."
        }
    }

    /// Banner after a tool is added (any source): it lands on disk but needs a broker restart to register.
    private func addedBanner(_ id: String, authored: Bool = false) -> String {
        "Added \(id)\(authored ? " (authored)" : ""). Restart the broker to register it, then grant a caller access."
    }

    /// Outcome of adding from a local folder: it landed, or the folder has no toolyard.toml (so the
    /// UI offers to author one), or it failed (with `error` set).
    enum AddOutcome { case added, needsManifest, failed }

    /// Add a tool by copying a local folder into the broker's tools dir. A folder without a
    /// toolyard.toml returns `.needsManifest` so the caller can open the authoring sheet.
    func addTool(source: String) async -> AddOutcome {
        busy = true
        error = nil
        defer { busy = false }
        do {
            let created = try await client.addTool(source: source)
            await refreshTools()
            banner = addedBanner(created.id)
            return .added
        } catch ApiError.http(422, _) {
            return .needsManifest
        } catch ApiError.unauthorized {
            authenticated = false; error = ApiError.unauthorized.message; return .failed
        } catch let apiError as ApiError {
            error = apiError.message; return .failed
        } catch let other {
            error = other.localizedDescription; return .failed
        }
    }

    /// Author a tool from a folder of code: copy it in and write the manifest you built in the app.
    func authorTool(source: String, manifest: [String: Any]) async -> Bool {
        await run {
            let created = try await self.client.addToolWithManifest(source: source, manifest: manifest)
            await self.refreshTools()
            self.banner = self.addedBanner(created.id, authored: true)
            return true
        } ?? false
    }

    /// Add a tool by cloning a git repo (optionally a subdir, at a branch/tag) into the tools dir.
    func addToolFromGitHub(repo: String, subdir: String, ref: String) async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            let created = try await client.addToolFromGitHub(repo: repo, subdir: subdir, ref: ref)
            await refreshTools()
            banner = addedBanner(created.id)
        } catch ApiError.http(422, _) {
            error = "That repo/subdir has no toolyard.toml — point at one that does, or add it from a local folder to author it."
        } catch ApiError.unauthorized {
            authenticated = false; error = ApiError.unauthorized.message
        } catch let apiError as ApiError {
            error = apiError.message
        } catch let other {
            error = other.localizedDescription
        }
    }

    @Published var secretBackend: SecretBackend?

    func refreshSecretBackend() async {
        await run { self.secretBackend = try await self.client.secretBackend() }
    }

    @Published var audit: AuditResponse?

    func refreshAudit() async {
        await run { self.audit = try await self.client.audit(limit: 100) }
    }

    /// Load a tool's secret set/unset status (returns it rather than storing — used by the sheet).
    func secretStatus(toolId: String) async -> SecretStatus? {
        await run { try await self.client.secretStatus(toolId: toolId) }
    }

    /// Provision a secret value into the vault. Returns whether it succeeded (the value is never stored here).
    func setSecretValue(toolId: String, field: String, value: String) async -> Bool {
        await run { try await self.client.setSecretValue(toolId: toolId, field: field, value: value) } ?? false
    }

    @Published var config: BrokerConfigInfo?

    func refreshConfig() async {
        await run { self.config = try await self.client.config() }
    }

    func saveConfig(port: Int, toolsRoot: String, nodURL: String, nodChannel: String,
                    nodToken: String?, approvalTTL: Int, rateLimit: Int) async {
        await run {
            self.config = try await self.client.saveConfig(
                port: port, toolsRoot: toolsRoot, nodURL: nodURL, nodChannel: nodChannel,
                nodToken: nodToken, approvalTTL: approvalTTL, rateLimit: rateLimit)
            self.banner = "Saved broker config. Restart the broker to apply."
        }
    }

    /// Load one caller's policy + enabled tools for the editors (returns it rather than storing).
    func loadPolicy(for caller: String) async -> PolicyResponse? {
        await run { try await self.client.policy(for: caller) }
    }

    func setEnabledTools(caller: String, enabled: [String]) async {
        await run {
            _ = try await self.client.setEnabledTools(caller: caller, enabled: enabled)
            await self.refreshCallers()
        }
    }

    func rotateToken(caller: String) async {
        await run {
            let result = try await self.client.rotateToken(caller: caller)
            self.banner = "New token for \(result.name) — copy it now, it won't be shown again:\n\(result.token)"
            await self.refreshCallers()
        }
    }

    func revokeCaller(_ caller: String) async {
        await run {
            _ = try await self.client.revokeCaller(caller)
            await self.refreshCallers()
        }
    }

    func savePolicy(caller: String, allow: [String], review: [String], deny: [String] = []) async {
        await run {
            _ = try await self.client.setPolicy(caller: caller, allow: allow, review: review, deny: deny)
            await self.refreshCallers()
        }
    }

    func refreshBroker() async {
        await run { self.broker = try await self.client.brokerStatus() }
    }

    func brokerAction(_ action: String) async {
        await run { self.broker = try await self.client.brokerAction(action) }
    }

    func refreshCallers() async {
        await run { self.callers = try await self.client.listCallers().callers }
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
    /// Returns the operation's value (nil if it threw); a Void operation returns an ignored Void?.
    @discardableResult
    private func run<T>(_ operation: @escaping () async throws -> T) async -> T? {
        busy = true
        error = nil
        defer { busy = false }
        do {
            return try await operation()
        } catch let apiError as ApiError {
            if case .unauthorized = apiError { authenticated = false }
            error = apiError.message
            return nil
        } catch let other {
            error = other.localizedDescription
            return nil
        }
    }
}
