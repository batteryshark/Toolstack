import Foundation

/// Memory-only editing state. Unknown mutation outcomes require a fresh comparison.
public struct PolicyDraft: Sendable {
    public enum Phase: Equatable, Sendable { case loading, loadFailed, editing, saving, rejected, unknown, conflict, saved }
    public let caller: String
    public var effects: [String: Effect] = [:]
    public private(set) var enabled: Set<String> = []
    public private(set) var baseline: [String: Effect] = [:]
    public private(set) var phase: Phase = .loading
    public var canSave: Bool { [.editing, .rejected, .conflict].contains(phase) }
    public var dirty: Bool { effects != baseline }
    public init(caller: String) { self.caller = caller }
    public mutating func loadFailed() { phase = .loadFailed }
    public mutating func load(_ response: PolicyResponse) {
        baseline = Self.flatten(response.policy)
        effects = baseline
        enabled = Set(response.enabled)
        phase = .editing
    }
    public mutating func beginSave() -> Bool {
        guard canSave else { return false }
        phase = .saving
        return true
    }
    public mutating func saved() { baseline = effects; phase = .saved }
    public mutating func failed(_ error: Error) {
        phase = MutationResult(error: error) == .rejected ? .rejected : .unknown
    }
    public mutating func compare(_ response: PolicyResponse) {
        let remote = Self.flatten(response.policy)
        enabled = Set(response.enabled)
        if remote == effects { baseline = remote; phase = .saved }
        else {
            let edited = Set(baseline.keys).union(effects.keys).filter { baseline[$0] != effects[$0] }
            var merged = remote
            for key in edited { merged[key] = effects[key] }
            effects = merged
            baseline = remote; phase = .conflict
        }
    }
    private static func flatten(_ policy: Policy) -> [String: Effect] {
        var result: [String: Effect] = [:]
        for (tool, ops) in policy.tools {
            for (op, raw) in ops where raw != "deny" { result["\(tool).\(op)"] = Effect(rawValue: raw) ?? .deny }
        }
        return result
    }
    public mutating func set(_ effect: Effect, for key: String) {
        if effect == .deny { effects.removeValue(forKey: key) } else { effects[key] = effect }
    }
}
