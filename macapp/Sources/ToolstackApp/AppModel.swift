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
    @Published private(set) var effectInFlight = false
    @Published var toolsError: String?
    private(set) var generation = UUID()
    @Published var policyDrafts: [String: PolicyDraft] = [:]
    @Published var enabledDrafts: [String: Set<String>] = [:]
    @Published var enabledOutcomes: [String: MutationResult] = [:]
    @Published var enabledBaselines: [String: Set<String>] = [:]
    struct Confirmation {
        let title: String
        let effect: String
        let action: () async -> Void
    }
    @Published var confirmation: Confirmation?
    @Published var uncertainMutation: String?
    @Published var continuationTarget: String?
    @Published private(set) var catalogObservation: CatalogObservation = .unknown
    private var catalogRevision = UUID()
    private var unknownRemovalTarget: String?
    func invalidateCatalog() { catalogRevision = UUID(); catalogObservation = .unknown }
    func registrationObserved(for id: String) -> Bool {
        catalogObservation.verified && catalogObservation.toolIDs.contains(id) && toolsError == nil && tools.contains { $0.id == id }
    }
    func refreshCatalog() async {
        guard !effectInFlight else { return }
        invalidateCatalog()
        let epoch = generation; let revision = catalogRevision; let activeClient = client
        var listed = false
        do {
            let rows = try await activeClient.listTools()
            guard epoch == generation, revision == catalogRevision else { return }
            tools = rows; toolsError = nil
            listed = true
            let observation = try await activeClient.catalogObservation()
            guard epoch == generation, revision == catalogRevision else { return }
            catalogObservation = observation
        } catch {
            guard epoch == generation, revision == catalogRevision else { return }
            catalogObservation = .unknown
            if !listed { toolsError = "Tool listing unavailable. Retained rows are last-known observations." }
        }
    }

    func writePolicy(_ draft: PolicyDraft) async -> PolicyDraft {
        let epoch = generation
        let activeClient = client
        var result = draft
        guard result.beginSave() else { return result }
        do {
            let receipt = try await activeClient.setPolicy(caller: draft.caller,
                allow: draft.effects.filter { $0.value == .allow }.map(\.key),
                review: draft.effects.filter { $0.value == .review }.map(\.key))
            guard receipt.name == draft.caller else {
                throw ApiError.decoding("Policy receipt caller does not match the draft")
            }
            result.compare(receipt)
        } catch { result.failed(error) }
        if epoch == generation { policyDrafts[draft.caller] = result }
        return result
    }

    func loadCallerSettings(_ caller: String) async throws -> SettingsSnapshot {
        let epoch = generation, activeClient = client
        let snapshot = try await activeClient.callerSettings(caller)
        guard epoch == generation else { throw CancellationError() }
        guard snapshot.name == caller, snapshot.callerId > 0 else { throw ApiError.decoding("Settings target differs from caller") }
        return snapshot
    }

    func writeCallerSettings(_ draft: CallerSettingsDraft) async -> CallerSettingsDraft {
        let epoch = generation, activeClient = client
        var result = draft
        guard result.canSave else { return result }
        result.phase = .saving
        do { try result.accept(try await activeClient.saveCallerSettings(draft)) }
        catch { result.phase = MutationResult(error: error) == .rejected ? .stale : .unknown }
        guard epoch == generation else { return draft }
        return result
    }

    /// The admin URL the user signs in against, editable on the login screen, remembered
    /// across launches. Works for a local admin (the default) or a remote one (a tailnet /
    /// tunnelled homeserver), as long as it's reachable.
    @Published var serverURL: String
    private var client: ApiClient
    private var tokenStorage: TokenStorage = .keychain
    private var refreshTask: Task<Void, Never>?
    private var draftServerURL: String?
    private static let urlDefaultsKey = "ToolstackAdminURL"
    init(client: ApiClient, serverURL: String, tokenStorage: TokenStorage = .keychain) {
        self.client = client; self.serverURL = serverURL; self.draftServerURL = serverURL
        self.tokenStorage = tokenStorage
    }

    func clearAdminState() {
        generation = UUID()
        refreshTask?.cancel(); refreshTask = nil
        authenticated = false; busy = false; effectInFlight = false
        uncertainMutation = nil; confirmation = nil; tools = []; toolsError = nil
        broker = nil; callers = []; error = nil; banner = nil
        config = nil; audit = nil; secretBackend = nil
        policyDrafts = [:]; enabledDrafts = [:]; enabledOutcomes = [:]; enabledBaselines = [:]
        draftServerURL = nil
        continuationTarget = nil
        unknownRemovalTarget = nil
        invalidateCatalog()
    }

    init() {
        if ProcessInfo.processInfo.arguments.contains("--snapshot-directory") {
            self.serverURL = "http://fake-admin.invalid"
            self.client = ApiClient(baseURL: URL(string: "http://fake-admin.invalid")!)
            return
        }
        let saved = UserDefaults.standard.string(forKey: AppModel.urlDefaultsKey)
        self.serverURL = saved ?? AppModel.adminURL().absoluteString
        self.client = ApiClient(baseURL: AppModel.adminURL())  // rebuilt from serverURL on login
    }

    /// The default admin URL: `$TOOLSTACK_ADMIN_URL` or loopback.
    nonisolated static func adminURL() -> URL {
        if let raw = ProcessInfo.processInfo.environment["TOOLSTACK_ADMIN_URL"],
           let url = URL(string: raw) { return url }
        return URL(string: "http://127.0.0.1:8780")!
    }

    func login(password: String) async {
        let trimmed = serverURL.trimmingCharacters(in: .whitespaces)
        guard let url = URL(string: trimmed), url.scheme != nil, url.host != nil else {
            error = "Enter a valid admin URL, e.g. http://127.0.0.1:8780"
            return
        }
        serverURL = trimmed
        if let previous = draftServerURL, previous != trimmed {
            clearAdminState()
        }
        draftServerURL = trimmed
        UserDefaults.standard.set(trimmed, forKey: AppModel.urlDefaultsKey)
        client = ApiClient(baseURL: url)   // point at whatever admin the user entered
        let activeClient = client
        let epoch = generation
        await run {
            let token = try await activeClient.login(password: password)
            guard epoch == self.generation else { return }
            self.tokenStorage.save(token, trimmed)   // remember it for next launch
            self.authenticated = true
            await self.refreshAll()
        }
    }

    /// On launch, try a token saved for the current admin URL. Validate it with a lightweight authed
    /// call; enter only on success. A 401 means it expired → forget it; any other error (admin
    /// unreachable) keeps it for next time and just stays on the login screen.
    func restoreSession() async {
        if CommandLine.arguments.contains("--snapshot-directory") { return }
        let epoch = generation
        defer { if epoch == generation { restoring = false } }
        let saved = serverURL.trimmingCharacters(in: .whitespaces)
        guard let url = URL(string: saved), url.host != nil,
              let token = tokenStorage.load(saved) else { return }
        let restored = ApiClient(baseURL: url)
        await restored.setToken(token)
        guard epoch == generation else { return }
        do {
            try await acceptRestoredSession(restored, account: saved)
        } catch ApiError.unauthorized {
            guard epoch == generation else { return }
            tokenStorage.delete(saved)
        } catch {
            // admin unreachable / transient; keep the token, let the user sign in manually
        }
    }

    /// Validates an already supplied client; credential loading stays in restoreSession.
    func acceptRestoredSession(_ restored: ApiClient, account: String) async throws {
        let epoch = generation
        _ = try await restored.brokerStatus()
        guard epoch == generation else { return }
        client = restored
        draftServerURL = account
        authenticated = true
        await refreshAll()
    }

    func logout() async {
        let account = draftServerURL ?? serverURL
        let oldClient = client
        clearAdminState()
        restoring = false
        tokenStorage.delete(account)
        try? await oldClient.logout()
    }

    func refreshAll() async {
        if CommandLine.arguments.contains("--snapshot-directory") { return }
        guard authenticated else { return }
        if let refreshTask { await refreshTask.value; return }
        let epoch = generation
        let task = Task { @MainActor in
            await self.refreshBroker()
            guard epoch == self.generation, self.authenticated, !Task.isCancelled else { return }
            await self.refreshCallers()
            guard epoch == self.generation, self.authenticated, !Task.isCancelled else { return }
            await self.refreshTools()
        }
        refreshTask = task
        await task.value
        if epoch == generation { refreshTask = nil }
    }

    /// Called on activation and each active-window timer tick. Observations only:
    /// drafts, sheet identity and uncertain mutation outcomes are left intact.
    func refreshWhileActive(_ active: Bool) async {
        guard active, authenticated, !effectInFlight, !busy else { return }
        await refreshAll()
    }

    func prepareCallerConfirmation(_ name: String) async -> Bool {
        let epoch = generation
        guard authenticated, !effectInFlight, uncertainMutation == nil else { return false }
        await refreshAll()
        guard epoch == generation, authenticated, error == nil,
              !effectInFlight, uncertainMutation == nil else { return false }
        return callers.contains { $0.name == name && $0.isActive }
    }

    @discardableResult
    func refreshTools() async -> Bool {
        if CommandLine.arguments.contains("--snapshot-directory") { return true }
        invalidateCatalog()
        let epoch = generation; let revision = catalogRevision
        let activeClient = client
        do {
            let rows = try await activeClient.listTools()
            guard epoch == generation, revision == catalogRevision else { return false }
            tools = rows; toolsError = nil; return true
        } catch {
            guard epoch == generation, revision == catalogRevision else { return false }
            toolsError = "Tool listing unavailable. Retained rows are last-known observations."
            return false
        }
    }

    /// Start / stop / restart a tool, then refresh so its row reflects the new run state.
    func toolAction(id: String, action: String, confirmed: Bool = false) async {
        guard uncertainMutation == nil, !effectInFlight else { return }
        if (action == "start" || action == "restart"), !confirmed {
            let epoch = generation
            let title = action == "start" ? "Start \(id)?" : "Restart \(id)?"
            let effect = "A started tool runs with this host's credentials. Only start tools you trust."
                + (action == "restart" ? " Stops and starts \(id), interrupting active calls. Requests will not be replayed." : "")
            confirmation = Confirmation(title: title, effect: effect) {
                guard epoch == self.generation else { return }
                await self.toolAction(id: id, action: action, confirmed: true)
            }
            return
        }
        effectInFlight = true
        invalidateCatalog()
        let epoch = generation
        let activeClient = client
        defer { if epoch == generation { effectInFlight = false } }
        var acknowledged = false
        do {
            _ = try await activeClient.toolAction(id: id, action: action)
            guard epoch == generation else { return }
            acknowledged = true
            let rows = try await activeClient.listTools()
            guard epoch == generation else { return }
            tools = rows; toolsError = nil
        } catch {
            guard epoch == generation else { return }
            if acknowledged || MutationResult(error: error) == .unknown { uncertainMutation = "\(action.capitalized) \(id): outcome unknown" }
            else { self.error = "\(action.capitalized) \(id) rejected. Reload state before retrying." }
        }
    }

    func compareMutationState() async {
        guard !effectInFlight, uncertainMutation != nil else { return }
        effectInFlight = true
        let epoch = generation; let revision = catalogRevision
        let activeClient = client
        defer { if epoch == generation { effectInFlight = false } }
        do {
            let latestBroker = try await activeClient.brokerStatus()
            guard epoch == generation, revision == catalogRevision else { return }
            let latestTools = try await activeClient.listTools()
            guard epoch == generation, revision == catalogRevision else { return }
            broker = latestBroker; tools = latestTools; toolsError = nil
            banner = "State reloaded. Review the broker and tool observations before another action."
            if let target = unknownRemovalTarget {
                banner = "Rechecked \(target): \(latestTools.contains { $0.id == target } ? "still listed (possibly another source)" : "not listed"). Filesystem outcome remains unknown."
                unknownRemovalTarget = nil
            }
            uncertainMutation = nil
        } catch { if epoch == generation, revision == catalogRevision { self.error = "Could not reload state. Outcome remains unknown." } }
    }

    func updateTool(id: String, description: String, secrets: [SecretDecl]) async {
        invalidateCatalog()
        let epoch = generation; let activeClient = client
        await run {
            _ = try await activeClient.updateTool(id: id, description: description, secrets: secrets)
            guard epoch == self.generation else { return }
            await self.refreshTools()
            guard epoch == self.generation else { return }
            self.banner = "Saved \(id). Restart the tool if you changed its secrets."
        }
    }

    /// Re-pull a tool from its recorded source, keeping the operator's description/secret edits.
    func resyncTool(id: String) async {
        invalidateCatalog()
        let epoch = generation; let activeClient = client
        await run {
            _ = try await activeClient.resyncTool(id: id)
            guard epoch == self.generation else { return }
            await self.refreshTools()
            guard epoch == self.generation else { return }
            self.banner = "Updated \(id) from its source. Restart the broker if its entrypoint or operations changed."
        }
    }

    func requestRemoval(_ tool: ToolInfo) {
        guard let external = tool.removable, !effectInFlight, uncertainMutation == nil else { return }
        let epoch = generation
        confirmation = Confirmation(title: "\(external ? "Unregister" : "Remove") \(tool.id)?",
            effect: external ? "Stops and unregisters \(tool.id). Files in \(tool.path ?? "its external folder") are retained. Other sources may still supply this id." : "Stops \(tool.id) and deletes its managed folder \(tool.path ?? tool.id). This cannot be undone.") {
                guard epoch == self.generation else { return }
                await self.removeTool(id: tool.id)
            }
    }
    func removeTool(id: String) async {
        guard !effectInFlight, uncertainMutation == nil else { return }
        effectInFlight = true
        error = nil
        banner = nil
        invalidateCatalog()
        let epoch = generation; let activeClient = client
        defer { if epoch == generation { effectInFlight = false } }
        do {
            let receipt = try await activeClient.removeToolReceipt(id: id)
            guard epoch == generation else { return }
            guard receipt.removed == id, let deleted = receipt.deleted else {
                unknownRemovalTarget = id
                uncertainMutation = "Remove/unregister \(id): filesystem outcome unknown. Reload and compare before another action."
                return
            }
            banner = deleted ? "Removed \(id)'s managed folder." : "Unregistered \(id); files retained. Other sources may still supply this id."
            _ = await refreshTools()
        } catch {
            guard epoch == generation else { return }
            if MutationResult(error: error) == .unknown { unknownRemovalTarget = id; uncertainMutation = "Remove/unregister \(id): outcome unknown" }
            else { self.error = "Remove/unregister \(id) rejected. \((error as? ApiError)?.message ?? "Reload before another action.")" }
        }
    }

    /// Banner after a tool is added (any source): it lands on disk but needs a broker restart to register.
    private func addedBanner(_ id: String, authored: Bool = false) -> String {
        "Added \(id)\(authored ? " (authored)" : ""). Folder copied; start separately, then review broker registration."
    }

    /// Outcome of adding from a local folder: it landed, or the folder has no toolyard.toml (so the
    /// UI offers to author one), or it failed (with `error` set).
    enum AddOutcome { case added, needsManifest, failed }

    /// Add a tool by copying a local folder into the broker's tools dir. A folder without a
    /// toolyard.toml returns `.needsManifest` so the caller can open the authoring sheet.
    func addTool(source: String) async -> AddOutcome {
        invalidateCatalog()
        let epoch = generation; let activeClient = client
        busy = true
        error = nil
        defer { if epoch == generation { busy = false } }
        do {
            let created = try await activeClient.addTool(source: source)
            guard epoch == generation else { return .failed }
            continuationTarget = created.id
            await refreshTools()
            guard epoch == generation else { return .failed }
            banner = addedBanner(created.id)
            return .added
        } catch ApiError.http(422, _) {
            guard epoch == generation else { return .failed }
            return .needsManifest
        } catch ApiError.unauthorized {
            guard epoch == generation else { return .failed }
            authenticated = false; error = ApiError.unauthorized.message; return .failed
        } catch let apiError as ApiError {
            guard epoch == generation else { return .failed }
            error = apiError.message; return .failed
        } catch let other {
            guard epoch == generation else { return .failed }
            error = other.localizedDescription; return .failed
        }
    }

    /// Author a tool from a folder of code: copy it in and write the manifest you built in the app.
    func authorTool(source: String, manifest: [String: Any]) async -> Bool {
        invalidateCatalog()
        let epoch = generation; let activeClient = client
        return await run {
            let created = try await activeClient.addToolWithManifest(source: source, manifest: manifest)
            guard epoch == self.generation else { return false }
            self.continuationTarget = created.id
            await self.refreshTools()
            guard epoch == self.generation else { return false }
            self.banner = self.addedBanner(created.id, authored: true)
            return true
        } ?? false
    }

    /// Add a tool by cloning a git repo (optionally a subdir, at a branch/tag) into the tools dir.
    func addToolFromGitHub(repo: String, subdir: String, ref: String) async {
        invalidateCatalog()
        let epoch = generation; let activeClient = client
        busy = true
        error = nil
        defer { if epoch == generation { busy = false } }
        do {
            let created = try await activeClient.addToolFromGitHub(repo: repo, subdir: subdir, ref: ref)
            guard epoch == generation else { return }
            continuationTarget = created.id
            await refreshTools()
            guard epoch == generation else { return }
            banner = addedBanner(created.id)
        } catch ApiError.http(422, _) {
            guard epoch == generation else { return }
            error = "That repo/subdir has no toolyard.toml. Point at one that does, or add it from a local folder to author it."
        } catch ApiError.unauthorized {
            guard epoch == generation else { return }
            authenticated = false; error = ApiError.unauthorized.message
        } catch let apiError as ApiError {
            guard epoch == generation else { return }
            error = apiError.message
        } catch let other {
            guard epoch == generation else { return }
            error = other.localizedDescription
        }
    }

    @Published var secretBackend: SecretBackend?
    func parseOpenAPI(_ spec: String) async -> ParsedOpenAPI? {
        let activeClient = client
        return await run { try await activeClient.parseOpenAPI(spec) }
    }

    func refreshSecretBackend() async {
        if CommandLine.arguments.contains("--snapshot-directory") { return }
        let activeClient = client
        let epoch = generation
        if let value = await run({ try await activeClient.secretBackend() }), epoch == generation { secretBackend = value }
    }

    @Published var audit: AuditResponse?

    func refreshAudit() async {
        if CommandLine.arguments.contains("--snapshot-directory") { return }
        let activeClient = client
        let epoch = generation
        if let value = await run({ try await activeClient.audit(limit: 100) }), epoch == generation { audit = value }
    }

    /// Load a tool's secret set/unset status (returns it rather than storing, used by the sheet).
    func secretStatus(toolId: String) async -> SecretStatus? {
        let activeClient = client
        return await run { try await activeClient.secretStatus(toolId: toolId) }
    }

    @Published var config: BrokerConfigInfo?

    func refreshConfig() async {
        if CommandLine.arguments.contains("--snapshot-directory") { return }
        let activeClient = client
        let epoch = generation
        if let value = await run({ try await activeClient.config() }), epoch == generation { config = value }
    }

    func saveConfig(port: Int, toolsRoot: String, nodURL: String, nodChannel: String,
                    nodToken: String?, approvalTTL: Int, rateLimit: Int) async {
        invalidateCatalog()
        let epoch = generation; let activeClient = client
        await run {
            let value = try await activeClient.saveConfig(
                port: port, toolsRoot: toolsRoot, nodURL: nodURL, nodChannel: nodChannel,
                nodToken: nodToken, approvalTTL: approvalTTL, rateLimit: rateLimit)
            guard epoch == self.generation else { return }
            self.config = value
            self.banner = "Saved broker config. Restart the broker to apply."
        }
    }

    /// Load one caller's policy + enabled tools for the editors (returns it rather than storing).
    func loadPolicy(for caller: String) async -> PolicyResponse? {
        let activeClient = client
        return await run { try await activeClient.policy(for: caller) }
    }

    func setEnabledTools(caller: String, enabled: [String]) async -> MutationResult {
        let epoch = generation; let activeClient = client
        do {
            _ = try await activeClient.setEnabledTools(caller: caller, enabled: enabled)
            guard epoch == generation else { return .unknown }
            return .success
        } catch { return epoch == generation ? MutationResult(error: error) : .unknown }
    }

    func rotateToken(caller: String, confirmed: Bool = false) async {
        if !confirmed {
            let epoch = generation
            guard await prepareCallerConfirmation(caller), epoch == generation else { return }
            confirmation = Confirmation(title: "Rotate token for \(caller)?", effect: "The existing token stops working. Update clients using \(caller).") {
                guard epoch == self.generation else { return }
                await self.rotateToken(caller: caller, confirmed: true)
            }
            return
        }
        let epoch = generation; let activeClient = client
        await run {
            let result = try await activeClient.rotateToken(caller: caller)
            guard epoch == self.generation else { return }
            self.banner = "New token for \(result.name). Copy it now, it won't be shown again:\n\(result.token)"
            await self.refreshCallers()
        }
    }

    func revokeCaller(_ caller: String) async {
        let epoch = generation; let activeClient = client
        await run {
            _ = try await activeClient.revokeCaller(caller)
            guard epoch == self.generation else { return }
            await self.refreshCallers()
        }
    }

    func savePolicy(caller: String, allow: [String], review: [String], deny: [String] = []) async -> Bool {
        let epoch = generation; let activeClient = client
        return await run {
            _ = try await activeClient.setPolicy(caller: caller, allow: allow, review: review, deny: deny)
            guard epoch == self.generation else { return false }
            await self.refreshCallers()
            return true
        } ?? false
    }

    func refreshBroker() async {
        if CommandLine.arguments.contains("--snapshot-directory") { return }
        let activeClient = client
        let epoch = generation
        if let value = await run({ try await activeClient.brokerStatus() }), epoch == generation { broker = value }
        else if epoch == generation { invalidateCatalog() }
    }

    func brokerAction(_ action: String, confirmed: Bool = false) async {
        guard uncertainMutation == nil, !effectInFlight else { return }
        if action == "restart", !confirmed {
            let epoch = generation
            confirmation = Confirmation(title: "Restart broker at \(serverURL)?", effect: "Interrupts broker availability and active calls. Reloads the tool catalog; requests will not be replayed.") {
                guard epoch == self.generation else { return }
                await self.brokerAction(action, confirmed: true)
            }
            return
        }
        effectInFlight = true
        invalidateCatalog()
        let revision = catalogRevision
        let epoch = generation
        let activeClient = client
        defer { if epoch == generation { effectInFlight = false } }
        var acknowledged = false
        do {
            _ = try await activeClient.brokerAction(action)
            guard epoch == generation else { return }
            acknowledged = true
            let status = try await activeClient.brokerStatus()
            guard epoch == generation else { return }
            let rows = try await activeClient.listTools()
            guard epoch == generation else { return }
            broker = status; tools = rows; toolsError = nil
            if action == "restart" {
                banner = "Broker restarted. Registration observation pending."
                let observation = (try? await activeClient.catalogObservation()) ?? .unknown
                guard epoch == generation else { return }
                if revision == catalogRevision { catalogObservation = observation }
            }
        } catch {
            guard epoch == generation else { return }
            if acknowledged || MutationResult(error: error) == .unknown { uncertainMutation = "Broker \(serverURL): \(action) outcome unknown" }
            else { self.error = "Broker \(action) rejected. Reload state before retrying." }
        }
    }

    func refreshCallers() async {
        if CommandLine.arguments.contains("--snapshot-directory") { return }
        let activeClient = client
        let epoch = generation
        if let value = await run({ try await activeClient.listCallers().callers }), epoch == generation { callers = value }
    }

    func createCaller(name: String) async {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        let epoch = generation; let activeClient = client
        await run {
            let created = try await activeClient.createCaller(name: trimmed)
            guard epoch == self.generation else { return }
            self.banner = "Token for \(created.name). Copy it now, it won't be shown again:\n\(created.token)"
            await self.refreshCallers()
        }
    }

    /// Run an async operation with busy/error bookkeeping; an `unauthorized` drops to login.
    /// Returns the operation's value (nil if it threw); a Void operation returns an ignored Void?.
    @discardableResult
    private func run<T>(_ operation: @escaping () async throws -> T) async -> T? {
        let epoch = generation
        busy = true
        error = nil
        defer { if epoch == generation { busy = false } }
        do {
            let result = try await operation()
            guard epoch == generation else { return nil }
            return result
        } catch let apiError as ApiError {
            guard epoch == generation else { return nil }
            if case .unauthorized = apiError { authenticated = false }
            error = apiError.message
            return nil
        } catch let other {
            guard epoch == generation else { return nil }
            error = other.localizedDescription
            return nil
        }
    }
}
