import Foundation
import CryptoKit

public struct SettingsPolicy: Codable, Equatable, Sendable {
    public var tools: [String: [String: String]]?
    public var enabled: [String]?
    public var disabledFunctions: [String: [String]]?
}

public struct SettingsSnapshot: Codable, Equatable, Sendable {
    public let name: String
    public let callerId: Int
    public let installation: String
    public let revision: String
    public let `operator`: String
    public var policy: SettingsPolicy
    public var enabled: [String]
    public let catalog: [String: [OpInfo]]
}

public struct SettingsReceipt: Decodable, Sendable {
    public let outcome: String
    public let name: String
    public let policy: SettingsPolicy
}

public struct SettingsValues: Codable, Equatable, Sendable {
    public var enabled: Set<String>
    public var excluded: [String: Set<String>]
    public var tools: [String: [String: String]]

    public init(_ snapshot: SettingsSnapshot) {
        enabled = Set(snapshot.enabled).intersection(snapshot.catalog.keys)
        excluded = [:]; tools = [:]
        for (tool, ops) in snapshot.catalog {
            excluded[tool] = Set(snapshot.policy.disabledFunctions?[tool] ?? []).intersection(ops.map(\.op))
            tools[tool] = Dictionary(uniqueKeysWithValues: ops.map {
                ($0.op, snapshot.policy.tools?[tool]?[$0.op] ?? "deny")
            })
        }
    }
    public func active(_ tool: String, _ op: String) -> Bool {
        enabled.contains(tool) && !(excluded[tool]?.contains(op) ?? false)
    }
    public func effect(_ tool: String, _ op: String) -> String { tools[tool]?[op] ?? "deny" }
}

public struct SettingsDifference: Identifiable, Sendable {
    public let id: String
    public let draft: String
    public let latest: String
}

/// Both tabs and their baseline are one durable draft. Comparing never edits it.
public struct CallerSettingsDraft: Codable, Equatable, Sendable {
    public enum Phase: String, Codable, Sendable { case editing, saving, unknown, stale, saved }
    public var snapshot: SettingsSnapshot
    public var baseline: SettingsValues
    public var values: SettingsValues
    public var phase: Phase = .editing
    public var tab = "enabled"
    public var search = ""
    public var enabledOnly = false
    public var needsReview = false
    public var expanded: Set<String> = []
    public var collapsedSearch: Set<String> = []
    public var dirty: Bool { values != baseline }
    public var canSave: Bool { phase == .editing && dirty }
    public var filtering: Bool { !search.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || enabledOnly || needsReview }
    public init(_ snapshot: SettingsSnapshot) {
        self.snapshot = snapshot; baseline = SettingsValues(snapshot); values = baseline
    }
    public func matches(_ tool: String) -> [OpInfo] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return (snapshot.catalog[tool] ?? []).filter {
            (query.isEmpty || "\(tool) \($0.op) \($0.description)".lowercased().contains(query)) &&
            (!enabledOnly || values.active(tool, $0.op)) &&
            (!needsReview || values.effect(tool, $0.op) == "review")
        }
    }
    public mutating func setTool(_ tool: String, enabled: Bool) {
        if enabled { values.enabled.insert(tool); values.excluded[tool] = [] }
        else { values.enabled.remove(tool) }
    }
    public mutating func setFunction(_ tool: String, _ op: String, enabled: Bool) {
        if enabled && !values.enabled.contains(tool) {
            values.enabled.insert(tool)
            values.excluded[tool] = Set(snapshot.catalog[tool, default: []].map(\.op))
        }
        if enabled { values.excluded[tool, default: []].remove(op) }
        else { values.excluded[tool, default: []].insert(op) }
    }
    public mutating func bulk(_ tool: String, enabled: Bool) {
        // Capture matches before changing enablement (Enabled only can remove rows).
        let visible = matches(tool)
        for op in visible { setFunction(tool, op.op, enabled: enabled) }
    }
    public mutating func observe(_ latest: SettingsSnapshot) {
        if phase != .unknown && (latest.revision != snapshot.revision || latest.installation != snapshot.installation) { phase = .stale }
    }
    public func canRebase(_ latest: SettingsSnapshot) -> Bool {
        latest.name == snapshot.name && latest.callerId == snapshot.callerId && latest.installation == snapshot.installation &&
        snapshot.catalog.allSatisfy { tool, ops in
            let current = Set(latest.catalog[tool, default: []].map(\.op))
            return latest.catalog[tool] != nil && Set(ops.map(\.op)).isSubset(of: current)
        }
    }
    public func differences(_ latest: SettingsSnapshot) -> [SettingsDifference] {
        let remote = SettingsValues(latest)
        var rows: [SettingsDifference] = []
        for tool in Set(snapshot.catalog.keys).union(latest.catalog.keys).sorted() {
            let local = values.enabled.contains(tool), saved = remote.enabled.contains(tool)
            if local != saved { rows.append(.init(id: "\(tool) / whole tool", draft: String(local), latest: String(saved))) }
            for op in Set(snapshot.catalog[tool, default: []].map(\.op)).union(latest.catalog[tool, default: []].map(\.op)).sorted() {
                let a = "\(values.active(tool, op) ? "Enabled" : "Disabled") / \(values.effect(tool, op))"
                let b = latest.catalog[tool]?.contains(where: { $0.op == op }) == true ?
                    "\(remote.active(tool, op) ? "Enabled" : "Disabled") / \(remote.effect(tool, op))" : "No longer available"
                if a != b { rows.append(.init(id: "\(tool) / \(op)", draft: a, latest: b)) }
            }
        }
        return rows
    }
    /// Explicitly invoked only after showing side-by-side comparison. Preserve remote
    /// unedited fields; do not discard edits for vanished functions or a different server.
    @discardableResult public mutating func keepEdits(on latest: SettingsSnapshot) -> Bool {
        guard canRebase(latest) else { return false }
        var merged = SettingsValues(latest)
        for (tool, ops) in snapshot.catalog {
            if baseline.enabled.contains(tool) != values.enabled.contains(tool) {
                if values.enabled.contains(tool) { merged.enabled.insert(tool) } else { merged.enabled.remove(tool) }
            }
            for op in ops.map(\.op) {
                if baseline.effect(tool, op) != values.effect(tool, op) { merged.tools[tool]?[op] = values.effect(tool, op) }
                let a = baseline.excluded[tool]?.contains(op) ?? false, b = values.excluded[tool]?.contains(op) ?? false
                if a != b {
                    if b { merged.excluded[tool, default: []].insert(op) } else { merged.excluded[tool, default: []].remove(op) }
                }
            }
        }
        snapshot = latest; baseline = SettingsValues(latest); values = merged; phase = .editing
        return true
    }
    public mutating func accept(_ receipt: SettingsReceipt) throws {
        guard receipt.outcome == "saved", receipt.name == snapshot.name else { throw ApiError.decoding("Wrong settings receipt") }
        var committed = snapshot; committed.policy = receipt.policy; committed.enabled = receipt.policy.enabled ?? []
        guard SettingsValues(committed) == values else { throw ApiError.decoding("Settings receipt differs from draft") }
        baseline = values; phase = .saved
    }
}

/// Device-local non-secret drafts, scoped to server, operator, installation and caller.
/// No tokens or CSRF values are serialized. Saving is owner-only and atomic.
public struct SettingsDraftStore: Sendable {
    public let directory: URL
    public init(directory: URL) { self.directory = directory }
    private func file(account: String, snapshot: SettingsSnapshot) -> URL {
        let scope = [account, snapshot.operator, snapshot.installation, snapshot.name, String(snapshot.callerId)]
        let data = try! JSONEncoder().encode(scope)
        let name = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent(name + ".json")
    }
    public func load(account: String, snapshot: SettingsSnapshot) throws -> CallerSettingsDraft? {
        let url = file(account: account, snapshot: snapshot)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        var draft = try JSONDecoder().decode(CallerSettingsDraft.self, from: Data(contentsOf: url))
        guard draft.snapshot.name == snapshot.name, draft.snapshot.callerId == snapshot.callerId, draft.snapshot.installation == snapshot.installation,
              draft.snapshot.operator == snapshot.operator else { return nil }
        if draft.phase == .saving { draft.phase = .unknown }
        draft.observe(snapshot)
        return draft
    }
    public func save(_ draft: CallerSettingsDraft, account: String) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let permissions = try fm.attributesOfItem(atPath: directory.path)
        guard permissions[.type] as? FileAttributeType == .typeDirectory,
              (permissions[.posixPermissions] as? NSNumber)?.intValue == 0o700 else {
            throw CocoaError(.fileWriteNoPermission)
        }
        let destination = file(account: account, snapshot: draft.snapshot)
        if !draft.dirty && draft.phase != .unknown && draft.phase != .saving && draft.phase != .stale {
            if fm.fileExists(atPath: destination.path) { try fm.removeItem(at: destination) }; return
        }
        let temporary = directory.appendingPathComponent(UUID().uuidString)
        guard fm.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw CocoaError(.fileWriteUnknown) }
        defer { try? fm.removeItem(at: temporary) }
        let handle = try FileHandle(forWritingTo: temporary)
        do { try handle.write(contentsOf: JSONEncoder().encode(draft)); try handle.synchronize(); try handle.close() }
        catch { try? handle.close(); throw error }
        if fm.fileExists(atPath: destination.path) { _ = try fm.replaceItemAt(destination, withItemAt: temporary) }
        else { try fm.moveItem(at: temporary, to: destination) }
    }
    public func discard(account: String, snapshot: SettingsSnapshot) throws {
        let url = file(account: account, snapshot: snapshot)
        if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
    }
}
