import AppKit
import SwiftUI
import ToolstackKit
import UniformTypeIdentifiers

/// Run as a bare SwiftPM executable (`swift run`), the process starts as a non-activating
/// (accessory) app, so its window can't take focus or come to the front. Force it to be a
/// normal foreground app on launch — Dock icon, focusable, ⌘-Tab. (A real `.app` bundle in
/// T-031 makes this implicit; this keeps `swift run` usable now.)
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.regular)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    // Keep running when the window closes — the app lives on in the menu bar (systray) and is
    // reopened from there ("Open Toolstack"). Quit explicitly from the menu bar or ⌘Q.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

/// App images bundled as SwiftPM resources. The menu-bar glyph is a template image (alpha-only),
/// so macOS tints it for the light/dark menu bar automatically.
enum AppImages {
    static let menuBar: NSImage = {
        let image = Bundle.module.url(forResource: "MenuBarIcon", withExtension: "png")
            .flatMap { NSImage(contentsOf: $0) }
            ?? NSImage(systemSymbolName: "square.stack.3d.up.fill", accessibilityDescription: "Toolstack")!
        image.isTemplate = true
        image.size = NSSize(width: 18, height: 18)
        return image
    }()
}

@main
struct ToolstackApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window("Toolstack", id: "main") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 760, minHeight: 520)
        }
        MenuBarExtra {
            MenuBarMenu().environmentObject(model)
        } label: {
            Image(nsImage: AppImages.menuBar)
        }
    }
}

/// The menu-bar (systray) menu: broker status at a glance, quick broker actions, and open/quit.
struct MenuBarMenu: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(statusLine)
        Divider()
        if model.authenticated {
            Button("Start broker") { Task { await model.brokerAction("start") } }
                .disabled(model.broker?.running == true || model.busy)
            Button("Stop broker") { Task { await model.brokerAction("stop") } }
                .disabled(model.broker?.running != true || model.busy)
            Button("Restart broker") { Task { await model.brokerAction("restart") } }
                .disabled(model.busy)
            Divider()
        }
        Button("Open Toolstack") {
            NSApplication.shared.activate(ignoringOtherApps: true)
            openWindow(id: "main")
        }
        Divider()
        Button("Quit Toolstack") { NSApplication.shared.terminate(nil) }
    }

    // Plain String (not a localized Text literal), so the port renders without a thousands separator.
    private var statusLine: String {
        guard model.authenticated else { return "Toolstack — not signed in" }
        guard let broker = model.broker else { return "Broker: —" }
        return broker.running ? "Broker: running" + (broker.port.map { " :\($0)" } ?? "") : "Broker: stopped"
    }
}

struct ContentView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if model.restoring {
                ProgressView("Connecting…").frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if model.authenticated {
                OperatorView()
            } else {
                LoginView()
            }
        }
        .task { await model.restoreSession() }   // resume a saved session on launch
        .overlay(alignment: .top) {
            if let error = model.error {
                Text(error)
                    .font(.callout).foregroundStyle(.white)
                    .padding(8).background(.red, in: .rect(cornerRadius: 8))
                    .padding(.top, 6)
            }
        }
    }
}

struct LoginView: View {
    @EnvironmentObject var model: AppModel
    @State private var password = ""

    var body: some View {
        VStack(spacing: 16) {
            Text("Toolstack").font(.largeTitle.bold())
            Text("Connect to an admin").foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 4) {
                Text("Admin URL").font(.caption).foregroundStyle(.secondary)
                TextField("http://127.0.0.1:8780", text: $model.serverURL)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
            }.frame(maxWidth: 360)
            VStack(alignment: .leading, spacing: 4) {
                Text("Admin password").font(.caption).foregroundStyle(.secondary)
                SecureField("password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { submit() }
            }.frame(maxWidth: 360)
            Button("Sign In", action: submit)
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || model.serverURL.isEmpty || model.busy)
        }
        .padding(40)
    }

    private func submit() {
        Task { await model.login(password: password); password = "" }
    }
}

struct OperatorView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            BrokerBar()
            Divider()
            if let banner = model.banner {
                HStack(alignment: .top) {
                    Text(banner).font(.callout.monospaced()).textSelection(.enabled)
                    Spacer()
                    Button { model.banner = nil } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.borderless).foregroundStyle(.secondary)
                }
                .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                .background(.green.opacity(0.15))
            }
            TabView {
                CallersPane().tabItem { Label("Callers", systemImage: "person.2") }
                ToolsPane().tabItem { Label("Tools", systemImage: "wrench.and.screwdriver") }
                ActivityPane().tabItem { Label("Activity", systemImage: "list.bullet.rectangle") }
                ConfigPane().tabItem { Label("Config", systemImage: "gearshape") }
            }
        }
        .task { await model.refreshAll() }
    }
}

/// A slim, full-width strip with broker status + start/stop/restart and sign-out. Replaces the old
/// left sidebar that held only these controls (a whole column for three buttons).
struct BrokerBar: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        let running = model.broker?.running == true
        HStack(spacing: 8) {
            Image(systemName: "server.rack").foregroundStyle(.secondary)
            Text("Broker").font(.headline)
            Circle().fill(running ? .green : .secondary).frame(width: 9, height: 9)
            Text(running ? "running" : "stopped").font(.callout).foregroundStyle(.secondary)
            if let port = model.broker?.port {
                Text(verbatim: ":\(port)").font(.caption).foregroundStyle(.secondary)  // no thousands separator
            }
            control("play.fill", "Start broker", disabled: running) { await model.brokerAction("start") }
            control("stop.fill", "Stop broker", disabled: !running) { await model.brokerAction("stop") }
            control("arrow.clockwise", "Restart broker", disabled: false) { await model.brokerAction("restart") }
            Spacer()
            Button("Sign Out") { Task { await model.logout() } }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }

    private func control(_ symbol: String, _ help: String, disabled: Bool,
                         _ action: @escaping () async -> Void) -> some View {
        Button { Task { await action() } } label: {
            Image(systemName: symbol).frame(width: 16)
        }
        .buttonStyle(.bordered)
        .help(help)
        .disabled(disabled || model.busy)
    }
}

struct CallersPane: View {
    @EnvironmentObject var model: AppModel
    @State private var newName = ""
    @State private var editing: Caller?       // caller whose policy is being edited
    @State private var enablingTools: Caller? // caller whose enabled-tools are being set
    @State private var revoking: Caller?      // caller pending revoke confirmation

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField("New caller name", text: $newName).textFieldStyle(.roundedBorder)
                Button("Add") { Task { await model.createCaller(name: newName); newName = "" } }
                    .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty || model.busy)
            }
            Table(model.callers) {
                TableColumn("Caller", value: \.name)
                TableColumn("Status") { caller in
                    Text(caller.isActive ? "active" : "revoked")
                        .foregroundStyle(caller.isActive ? .primary : .secondary)
                }
                TableColumn("") { caller in
                    if caller.isActive {
                        Menu {
                            Button("Enabled tools…") { enablingTools = caller }
                            Button("Edit policy…") { editing = caller }
                            Button("Rotate token") { Task { await model.rotateToken(caller: caller.name) } }
                            Divider()
                            Button("Revoke caller", role: .destructive) { revoking = caller }
                        } label: { Image(systemName: "ellipsis.circle") }
                        .menuStyle(.borderlessButton).fixedSize()
                    }
                }
            }
        }
        .padding()
        .navigationTitle("Callers")
        .sheet(item: $editing) { caller in
            PolicyEditor(caller: caller.name).environmentObject(model)
        }
        .sheet(item: $enablingTools) { caller in
            EnabledToolsEditor(caller: caller.name).environmentObject(model)
        }
        .confirmationDialog("Revoke caller?", isPresented: revokingBinding, presenting: revoking) { caller in
            Button("Revoke \(caller.name)", role: .destructive) {
                Task { await model.revokeCaller(caller.name) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { caller in
            Text("Disables “\(caller.name)” and cancels its pending approvals. This can't be undone.")
        }
    }

    private var revokingBinding: Binding<Bool> {
        Binding(get: { revoking != nil }, set: { if !$0 { revoking = nil } })
    }
}

struct ToolsPane: View {
    @EnvironmentObject var model: AppModel
    @State private var editing: ToolInfo?
    @State private var managingSecrets: ToolInfo?
    @State private var addingTool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerBar
            Divider()
            if model.tools.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "wrench.and.screwdriver").font(.largeTitle).foregroundStyle(.secondary)
                    Text("No tools registered").foregroundStyle(.secondary)
                    Text("Author tools into the broker's tools dir, then restart it.")
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.tools) { tool in
                    DisclosureGroup {
                        HStack(alignment: .top) {
                            if tool.description.isEmpty {
                                Text("No description.").font(.callout).foregroundStyle(.secondary)
                            } else {
                                Text(tool.description).font(.callout)
                            }
                            Spacer()
                            Button("Edit…") { editing = tool }.font(.caption)
                            if let source = tool.source {
                                Menu {
                                    Button("Update from \(sourceKind(source))") {
                                        Task { await model.resyncTool(id: tool.id) }
                                    }
                                } label: { Image(systemName: "ellipsis.circle") }
                                    .menuStyle(.borderlessButton).fixedSize()
                                    .help("Re-pull this tool from its source")
                            }
                        }
                        .padding(.vertical, 2)
                        if let source = tool.source {
                            Text(sourceProvenance(source)).font(.caption2).foregroundStyle(.secondary)
                        }
                        if !tool.ops.isEmpty {
                            Divider().padding(.vertical, 2)
                            Text("Operations").font(.caption.bold()).foregroundStyle(.secondary)
                            ForEach(tool.ops) { op in opRow(op) }
                        }
                        Divider().padding(.vertical, 2)
                        HStack {
                            Text("Secrets").font(.caption.bold()).foregroundStyle(.secondary)
                            Spacer()
                            if model.secretBackend?.name == "vault" && !tool.secrets.isEmpty {
                                Button("Set values…") { managingSecrets = tool }.font(.caption)
                            }
                        }
                        if tool.secrets.isEmpty {
                            Text("No secrets declared.").font(.caption).foregroundStyle(.secondary)
                        } else {
                            ForEach(tool.secrets) { secretRow($0) }
                        }
                    } label: {
                        HStack(spacing: 8) {
                            Circle().fill(tool.running ? .green : .secondary).frame(width: 8, height: 8)
                            Text(tool.id).bold()
                            Text(tool.type).font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            toolControl("play.fill", "Start", disabled: tool.running) {
                                await model.toolAction(id: tool.id, action: "start")
                            }
                            toolControl("stop.fill", "Stop", disabled: !tool.running) {
                                await model.toolAction(id: tool.id, action: "stop")
                            }
                            toolControl("arrow.clockwise", "Restart", disabled: false) {
                                await model.toolAction(id: tool.id, action: "restart")
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Tools")
        .sheet(item: $editing) { tool in
            ToolEditor(tool: tool).environmentObject(model)
        }
        .sheet(item: $managingSecrets) { tool in
            SecretValuesSheet(tool: tool).environmentObject(model)
        }
        .task { await model.refreshTools(); await model.refreshSecretBackend() }
    }

    private var headerBar: some View {
        HStack(spacing: 6) {
            if let backend = model.secretBackend {
                Image(systemName: "key.fill").font(.caption).foregroundStyle(.secondary)
                Text("Secret backend:").foregroundStyle(.secondary)
                Text(backend.name).bold()
                if let detail = backend.path ?? backend.host, !detail.isEmpty {
                    Text("· \(detail)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer()
            Button { addingTool = true } label: { Label("Add tool", systemImage: "plus") }
                .sheet(isPresented: $addingTool) { AddToolSheet().environmentObject(model) }
        }
        .padding(.horizontal).padding(.vertical, 8)
    }

    private func sourceKind(_ source: ToolSource) -> String {
        source.type == "github" ? "GitHub" : "folder"
    }

    private func sourceProvenance(_ source: ToolSource) -> String {
        if source.type == "github" {
            let sub = (source.subdir?.isEmpty == false) ? " /\(source.subdir!)" : ""
            let ref = (source.ref?.isEmpty == false) ? " @\(source.ref!)" : ""
            return "from \(source.url ?? "a git repo")\(sub)\(ref)"
        }
        return "from \(source.source ?? "a folder")"
    }

    // A compact per-row lifecycle button. .borderless so a tap hits the button, not the disclosure.
    private func toolControl(_ symbol: String, _ help: String, disabled: Bool,
                             _ action: @escaping () async -> Void) -> some View {
        Button { Task { await action() } } label: { Image(systemName: symbol) }
            .buttonStyle(.borderless)
            .help(help)
            .disabled(disabled || model.busy)
    }

    private func opRow(_ op: OpInfo) -> some View {
        HStack {
            Text(op.op).bold()
            Text(op.risk).font(.caption2).padding(.horizontal, 5).padding(.vertical, 1)
                .background(.secondary.opacity(0.15), in: .capsule)
            Spacer()
            Text(op.description).font(.caption).foregroundStyle(.secondary)
        }
    }

    private func secretRow(_ secret: SecretDecl) -> some View {
        HStack(spacing: 6) {
            Text(secret.name).bold()
            Image(systemName: "arrow.right").font(.caption2).foregroundStyle(.secondary)
            Text(secret.field).font(.caption).foregroundStyle(.secondary)
            if secret.writable {
                Text("writable").font(.caption2).padding(.horizontal, 5).padding(.vertical, 1)
                    .background(.orange.opacity(0.2), in: .capsule)
            }
            if let vault = secret.vault, !vault.isEmpty {
                Text(vault).font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}

/// One editable rest path rule: a verb, a path glob (blank = any path), and an effect.
struct EditableRule: Identifiable {
    let id = UUID()
    var verb: String
    var pattern: String
    var effect: Effect
}

/// Per-caller policy editor. For api/mcp tools it's an allow / review / deny picker per op.
/// For a rest tool it edits PATH RULES: (verb, path-glob, effect) rows — most-specific wins,
/// an unmatched path is denied, and an explicit deny carves a hole inside a broader allow.
struct PolicyEditor: View {
    @EnvironmentObject var model: AppModel
    let caller: String
    @Environment(\.dismiss) private var dismiss
    @State private var effects: [String: Effect] = [:]            // "tool.op" -> effect (api/mcp)
    @State private var restRules: [String: [EditableRule]] = [:]  // tool id -> path rules (rest)
    @State private var enabled: Set<String> = []
    @State private var loaded = false

    private var enabledTools: [ToolInfo] { model.tools.filter { enabled.contains($0.id) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Policy — \(caller)").font(.title2.bold())
                Spacer()
                Button("Allow all") { setAll(.allow) }.disabled(!loaded || effects.isEmpty)
                Button("Deny all") { setAll(.deny) }.disabled(!loaded || effects.isEmpty)
            }
            if !loaded {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if enabledTools.isEmpty {
                VStack(spacing: 6) {
                    Text("No tools enabled for this caller.").foregroundStyle(.secondary)
                    Text("Add some via the caller's ••• menu → “Enabled tools”.")
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(enabledTools) { tool in
                        Section(tool.id) {
                            if tool.type == "rest" { restEditor(tool) }
                            else { ForEach(tool.ops) { op in opRow(tool: tool, op: op) } }
                        }
                    }
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { Task { await save() } }
                    .keyboardShortcut(.defaultAction).disabled(!loaded || model.busy)
            }
        }
        .padding()
        .frame(minWidth: 560, minHeight: 480)
        .task { await load() }
    }

    @ViewBuilder
    private func opRow(tool: ToolInfo, op: OpInfo) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(op.op).bold()
                Text(op.risk).font(.caption2)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(.secondary.opacity(0.15), in: .capsule)
                Spacer()
            }
            if !op.description.isEmpty {
                Text(op.description).font(.caption).foregroundStyle(.secondary)
            }
            Picker("", selection: bind("\(tool.id).\(op.op)")) {
                ForEach(Effect.allCases) { Text($0.rawValue.capitalized).tag($0) }
            }.pickerStyle(.segmented).labelsHidden()
        }.padding(.vertical, 2)
    }

    @ViewBuilder
    private func restEditor(_ tool: ToolInfo) -> some View {
        let verbs = tool.ops.map(\.op)   // the verbs this tool exposes
        Text("Path rules — most specific wins; a path matching no rule is denied.")
            .font(.caption).foregroundStyle(.secondary)
        ForEach(rulesBinding(tool.id)) { $rule in
            HStack(spacing: 6) {
                Picker("", selection: $rule.verb) {
                    ForEach(verbs, id: \.self) { Text($0).tag($0) }
                }.labelsHidden().frame(width: 92)
                TextField("/path/**  (blank = any path)", text: $rule.pattern)
                Picker("", selection: $rule.effect) {
                    ForEach(Effect.allCases) { Text($0.rawValue.capitalized).tag($0) }
                }.pickerStyle(.segmented).labelsHidden().frame(width: 170)
                Button(role: .destructive) { removeRule(tool.id, rule.id) } label: { Image(systemName: "trash") }
                    .buttonStyle(.borderless)
            }
        }
        Button {
            restRules[tool.id, default: []].append(
                EditableRule(verb: verbs.first ?? "GET", pattern: "", effect: .allow))
        } label: { Label("Add rule", systemImage: "plus") }.font(.caption)
    }

    private func bind(_ key: String) -> Binding<Effect> {
        Binding(get: { effects[key] ?? .deny }, set: { effects[key] = $0 })
    }

    private func rulesBinding(_ tool: String) -> Binding<[EditableRule]> {
        Binding(get: { restRules[tool] ?? [] }, set: { restRules[tool] = $0 })
    }

    private func removeRule(_ tool: String, _ id: UUID) {
        restRules[tool]?.removeAll { $0.id == id }
    }

    private func setAll(_ effect: Effect) {
        for key in Array(effects.keys) { effects[key] = effect }
    }

    private func load() async {
        await model.refreshTools()
        guard let resp = await model.loadPolicy(for: caller) else { loaded = true; return }
        enabled = Set(resp.enabled)
        var ops: [String: Effect] = [:]
        var rules: [String: [EditableRule]] = [:]
        for tool in enabledTools {
            if tool.type == "rest" {
                rules[tool.id] = (resp.policy.tools[tool.id] ?? [:]).map { key, value in
                    // a key is "<VERB>" or "<VERB> <path-glob>"
                    let parts = key.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false)
                    return EditableRule(verb: String(parts[0]),
                                        pattern: parts.count > 1 ? String(parts[1]) : "",
                                        effect: Effect(rawValue: value) ?? .deny)
                }.sorted { ($0.verb, $0.pattern) < ($1.verb, $1.pattern) }
            } else {
                for op in tool.ops { ops["\(tool.id).\(op.op)"] = resp.policy.effect(tool: tool.id, op: op.op) }
            }
        }
        effects = ops
        restRules = rules
        loaded = true
    }

    private func save() async {
        var allow: [String] = [], review: [String] = [], deny: [String] = []
        // api/mcp ops: allow/review listed; deny == omitted (absent is denied)
        for (key, effect) in effects {
            if effect == .allow { allow.append(key) } else if effect == .review { review.append(key) }
        }
        // rest path rules: "tool.VERB" or "tool.VERB pattern"; deny is explicit (a carve-out)
        for (tool, rules) in restRules {
            for rule in rules where !rule.verb.isEmpty {
                let p = rule.pattern.trimmingCharacters(in: .whitespaces)
                let spec = p.isEmpty ? "\(tool).\(rule.verb)" : "\(tool).\(rule.verb) \(p)"
                switch rule.effect {
                case .allow: allow.append(spec)
                case .review: review.append(spec)
                case .deny: deny.append(spec)
                }
            }
        }
        await model.savePolicy(caller: caller, allow: allow, review: review, deny: deny)
        dismiss()
    }
}

/// Which tools a caller is enabled for (gates the policy editor). Toggling a tool off also drops
/// its granted ops on the broker side.
struct EnabledToolsEditor: View {
    @EnvironmentObject var model: AppModel
    let caller: String
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<String> = []
    @State private var loaded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Enabled tools — \(caller)").font(.title2.bold())
            Text("Which tools this caller may use. The policy editor shows ops for these.")
                .font(.caption).foregroundStyle(.secondary)
            if !loaded {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if model.tools.isEmpty {
                Text("No tools registered.").foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.tools) { tool in
                    Toggle(isOn: toggle(tool.id)) {
                        HStack {
                            Text(tool.id).bold()
                            Text(tool.type).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { Task { await save() } }
                    .keyboardShortcut(.defaultAction).disabled(!loaded || model.busy)
            }
        }
        .padding()
        .frame(minWidth: 420, minHeight: 360)
        .task { await load() }
    }

    private func toggle(_ id: String) -> Binding<Bool> {
        Binding(get: { selected.contains(id) },
                set: { if $0 { selected.insert(id) } else { selected.remove(id) } })
    }

    private func load() async {
        await model.refreshTools()
        if let resp = await model.loadPolicy(for: caller) { selected = Set(resp.enabled) }
        loaded = true
    }

    private func save() async {
        await model.setEnabledTools(caller: caller, enabled: Array(selected))
        dismiss()
    }
}

/// Edit a tool's description and its secret DECLARATIONS (not values, and not its ops/entrypoint —
/// those are authored on the filesystem and preserved server-side). Maps to `POST /api/tools/{id}`.
struct ToolEditor: View {
    let tool: ToolInfo
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var description: String
    @State private var secrets: [EditableSecret]
    @State private var saveError: String?

    init(tool: ToolInfo) {
        self.tool = tool
        _description = State(initialValue: tool.description)
        _secrets = State(initialValue: tool.secrets.map(EditableSecret.init(from:)))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Edit tool — \(tool.id)").font(.title2.bold())
            Form {
                Section("Description") {
                    TextField("What this tool does", text: $description, axis: .vertical)
                        .lineLimit(2...5)
                }
                Section {
                    if secrets.isEmpty {
                        Text("No secrets declared.").foregroundStyle(.secondary)
                    }
                    ForEach(secrets) { sec in
                        secretRow(binding(for: sec)) { secrets.removeAll { $0.id == sec.id } }
                    }
                    Button { secrets.append(EditableSecret()) } label: {
                        Label("Add secret", systemImage: "plus")
                    }
                } header: {
                    Text("Secret declarations")
                } footer: {
                    Text("Declarations only — the file the tool reads (name) and the backend key (field). "
                         + "Values stay in the \(model.secretBackend?.name ?? "secret") backend. "
                         + "Saving rewrites toolyard.toml (operations are kept; comments are not).")
                        .font(.caption)
                }
            }
            .formStyle(.grouped)
            HStack {
                if let saveError {
                    Label(saveError, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.red).lineLimit(2)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { Task { await save() } }
                    .keyboardShortcut(.defaultAction).disabled(model.busy)
            }
        }
        .padding()
        .frame(minWidth: 540, minHeight: 480)
    }

    private func secretRow(_ sec: Binding<EditableSecret>, onDelete: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                TextField("name (file)", text: sec.name)
                TextField("field (backend key)", text: sec.field)
                Toggle("writable", isOn: sec.writable).toggleStyle(.checkbox).fixedSize()
                Button(role: .destructive, action: onDelete) { Image(systemName: "trash") }
                    .buttonStyle(.borderless)
            }
            HStack {
                TextField("vault (Infisical, optional)", text: sec.vault)
                TextField("item (Infisical, optional)", text: sec.item)
            }
            .font(.caption).foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }

    /// An id-keyed binding so editing/deleting stays correct even as rows are added/removed
    /// (no reliance on array indices, which can go stale mid-render).
    private func binding(for sec: EditableSecret) -> Binding<EditableSecret> {
        Binding(
            get: { secrets.first { $0.id == sec.id } ?? sec },
            set: { newValue in
                if let i = secrets.firstIndex(where: { $0.id == sec.id }) { secrets[i] = newValue }
            })
    }

    private func save() async {
        let decls: [SecretDecl] = secrets.compactMap { row in
            let name = row.name.trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { return nil }   // a blank row is dropped, mirroring the server
            let vault = row.vault.trimmingCharacters(in: .whitespaces)
            let item = row.item.trimmingCharacters(in: .whitespaces)
            return SecretDecl(name: name,
                              field: row.field.trimmingCharacters(in: .whitespaces),
                              writable: row.writable,
                              vault: vault.isEmpty ? nil : vault,
                              item: item.isEmpty ? nil : item)
        }
        await model.updateTool(id: tool.id, description: description, secrets: decls)
        // Keep the sheet (and edits) open if the server rejected it, surfacing why inline — the
        // dashboard banner would be hidden behind this sheet.
        if model.error == nil { dismiss() } else { saveError = model.error }
    }
}

/// A mutable secret-declaration row for the tool editor (converted to `SecretDecl` on save).
struct EditableSecret: Identifiable {
    let id = UUID()
    var name: String
    var field: String
    var writable: Bool
    var vault: String
    var item: String

    init(from decl: SecretDecl) {
        name = decl.name; field = decl.field; writable = decl.writable
        vault = decl.vault ?? ""; item = decl.item ?? ""
    }

    init() { name = ""; field = ""; writable = false; vault = ""; item = "" }
}

/// Provision a tool's secret VALUES into the local vault. Values are write-only — typed into a
/// SecureField, sent, and never shown back; the sheet only knows set/unset status per field.
struct SecretValuesSheet: View {
    let tool: ToolInfo
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var status: SecretStatus?
    @State private var entries: [String: String] = [:]   // field -> the value being typed
    @State private var saving: String?                    // field currently being saved
    @State private var note: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Secret values — \(tool.id)").font(.title2.bold())
            Text("Stored in the local encrypted vault. Values are write-only — they're saved, never "
                 + "shown back. Restart the tool to pick up a change.")
                .font(.caption).foregroundStyle(.secondary)
            if status == nil {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(tool.secrets) { secretRow($0) }
            }
            HStack {
                if let note { Text(note).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding().frame(minWidth: 540, minHeight: 360)
        .task { status = await model.secretStatus(toolId: tool.id) }
    }

    private func secretRow(_ secret: SecretDecl) -> some View {
        let isSet = status?.provisioned.contains(secret.field) ?? false
        return HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(secret.name).bold()
                    Image(systemName: "arrow.right").font(.caption2).foregroundStyle(.secondary)
                    Text(secret.field).font(.caption).foregroundStyle(.secondary)
                    Text(isSet ? "set" : "not set").font(.caption2)
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background((isSet ? Color.green : .orange).opacity(0.2), in: .capsule)
                }
                SecureField("new value", text: binding(secret.field))
                    .textFieldStyle(.roundedBorder).frame(maxWidth: 300)
                    .onSubmit { Task { await save(secret.field) } }
            }
            Spacer()
            Button(saving == secret.field ? "Saving…" : "Save") { Task { await save(secret.field) } }
                .disabled((entries[secret.field] ?? "").isEmpty || saving != nil)
        }.padding(.vertical, 3)
    }

    private func binding(_ field: String) -> Binding<String> {
        Binding(get: { entries[field] ?? "" }, set: { entries[field] = $0 })
    }

    private func save(_ field: String) async {
        let value = entries[field] ?? ""
        guard !value.isEmpty else { return }
        saving = field
        let ok = await model.setSecretValue(toolId: tool.id, field: field, value: value)
        saving = nil
        if ok {
            entries[field] = ""                                    // clear the typed value
            note = "Saved \(field)."
            status = await model.secretStatus(toolId: tool.id)     // refresh set/unset
        } else {
            note = model.error
        }
    }
}

/// Add a tool by pointing at a folder that contains a toolyard.toml. The path is on the ADMIN's
/// machine: for a local admin that's this Mac (use "Choose…"); for a remote/Docker admin, type a
/// path it can see. The folder is copied into the broker's managed tools dir.
struct AddToolSheet: View {
    enum Mode: String, CaseIterable, Identifiable {
        case folder = "Local folder", github = "GitHub"
        var id: String { rawValue }
    }

    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var mode: Mode = .folder
    @State private var path = ""
    @State private var repo = ""
    @State private var subdir = ""
    @State private var ref = ""
    @State private var picking = false
    @State private var addError: String?
    @State private var authoringFor: String?   // set when a picked folder has no toolyard.toml

    var body: some View {
        if let source = authoringFor {
            // The folder is code with no manifest — author one in place (the "Either" other half).
            ToolAuthoringForm(source: source, onCreated: { dismiss() }, onBack: { authoringFor = nil })
                .environmentObject(model)
        } else {
            addForm
        }
    }

    @ViewBuilder private var addForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add a tool").font(.title2.bold())
            Picker("", selection: $mode) {
                ForEach(Mode.allCases) { Text($0.rawValue).tag($0) }
            }.pickerStyle(.segmented).labelsHidden()

            if mode == .folder { folderFields } else { githubFields }

            HStack {
                if let addError {
                    Label(addError, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.red).lineLimit(3)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Add") { Task { await add() } }
                    .keyboardShortcut(.defaultAction).disabled(!canAdd || model.busy)
            }
        }
        .padding()
        .frame(minWidth: 520, minHeight: 230)
        .fileImporter(isPresented: $picking, allowedContentTypes: [.folder]) { result in
            if case .success(let url) = result { path = url.path }   // a local pick fills the field
        }
    }

    @ViewBuilder private var folderFields: some View {
        Text("Point at a folder containing a toolyard.toml. The path is on the admin's machine — "
             + "for a local admin that's this Mac; for a remote or Docker admin, a path it can see.")
            .font(.caption).foregroundStyle(.secondary)
        HStack {
            TextField("/path/to/tool-folder", text: $path).textFieldStyle(.roundedBorder)
            Button("Choose…") { picking = true }
        }
    }

    @ViewBuilder private var githubFields: some View {
        Label("Cloning runs third-party code when you later start the tool. Review it and grant "
              + "callers access deliberately — nothing runs just from adding it.",
              systemImage: "exclamationmark.shield")
            .font(.caption).foregroundStyle(.secondary)
        TextField("https://github.com/owner/repo", text: $repo).textFieldStyle(.roundedBorder)
        HStack {
            TextField("subdir (optional)", text: $subdir).textFieldStyle(.roundedBorder)
            TextField("branch/tag (optional)", text: $ref).textFieldStyle(.roundedBorder)
        }
    }

    private var canAdd: Bool {
        let field = mode == .folder ? path : repo
        return !field.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private func add() async {
        switch mode {
        case .folder:
            let source = path.trimmingCharacters(in: .whitespaces)
            switch await model.addTool(source: source) {
            case .added: dismiss()
            case .needsManifest: addError = nil; authoringFor = source   // morph into the authoring form
            case .failed: addError = model.error
            }
        case .github:
            await model.addToolFromGitHub(repo: repo.trimmingCharacters(in: .whitespaces),
                                          subdir: subdir.trimmingCharacters(in: .whitespaces),
                                          ref: ref.trimmingCharacters(in: .whitespaces))
            if model.error == nil { dismiss() } else { addError = model.error }
        }
    }
}

/// A mutable operation row for the authoring form (→ a manifest `[[operations]]` entry).
struct EditableOp: Identifiable {
    let id = UUID()
    var name = ""
    var risk = "read"
    var description = ""
    var args: [EditableArg] = []
}

/// A mutable argument row (→ an operation's `args` entry).
struct EditableArg: Identifiable {
    let id = UUID()
    var name = ""
    var type = "string"
    var required = false
}

/// Author a tool's manifest for a folder of code that has no toolyard.toml — id, entrypoint,
/// operations (+ args), and secret declarations. The server normalizes + validates, so it reports
/// precise errors (bad id, port range, missing op, …) inline.
struct ToolAuthoringForm: View {
    let source: String
    let onCreated: () -> Void
    let onBack: () -> Void

    @EnvironmentObject var model: AppModel
    @State private var id = ""
    @State private var type = "api"
    @State private var description = ""
    @State private var command = ""
    @State private var image = ""
    @State private var port = ""
    @State private var operations: [EditableOp] = [EditableOp()]
    @State private var secrets: [EditableSecret] = []
    @State private var saveError: String?

    private let risks = ["read", "write", "destructive"]   // matches admin RISK_CHOICES
    private let toolTypes = ["api", "mcp", "rest"]          // matches admin TOOL_TYPES
    private let restVerbs = ["GET", "POST", "PUT", "PATCH", "DELETE"]  // matches admin REST_VERBS
    private let argTypes = ["string", "number", "integer", "boolean", "object", "array"]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Button { onBack() } label: { Label("Back", systemImage: "chevron.left") }.buttonStyle(.borderless)
                Spacer()
            }
            Text("Author a tool").font(.title2.bold())
            Text("No toolyard.toml in \(source) — describe the tool. The folder is copied into the "
                 + "broker's tools dir with the manifest you write here.")
                .font(.caption).foregroundStyle(.secondary).lineLimit(2)
            Form {
                Section("Tool") {
                    TextField("id (letters, digits, _ or -)", text: $id)
                    Picker("transport", selection: $type) {
                        ForEach(toolTypes, id: \.self) { Text($0).tag($0) }
                    }
                    TextField("description (optional)", text: $description, axis: .vertical).lineLimit(1...3)
                }
                Section {
                    TextField("command — e.g. python3 app.py", text: $command)
                    TextField("image (docker, optional)", text: $image)
                    TextField("port", text: $port)
                } header: { Text("Entrypoint") } footer: {
                    Text(entrypointHint).font(.caption)
                }
                Section {
                    ForEach(operations) { op in opEditor(op) }
                    Button { operations.append(EditableOp()) } label: { Label("Add operation", systemImage: "plus") }
                } header: { Text("Operations") } footer: {
                    if type == "rest" {
                        Text("A rest op IS an HTTP verb; the agent passes {path, body, query}. Risk is derived from the verb and arguments are set automatically.")
                            .font(.caption)
                    }
                }
                Section("Secrets (optional)") {
                    ForEach(secrets) { sec in secretEditor(sec) }
                    Button { secrets.append(EditableSecret()) } label: { Label("Add secret", systemImage: "plus") }
                }
            }
            .formStyle(.grouped)
            HStack {
                if let saveError {
                    Label(saveError, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.red).lineLimit(3)
                }
                Spacer()
                Button("Create tool") { Task { await create() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(id.trimmingCharacters(in: .whitespaces).isEmpty || model.busy)
            }
        }
        .padding()
        .frame(minWidth: 580, minHeight: 560)
    }

    private var entrypointHint: String {
        switch type {
        case "mcp":
            return "An mcp tool is a streamable-HTTP MCP server: it serves /mcp on this port; the broker calls it via tools/call (op = MCP tool name)."
        case "rest":
            return "A rest tool is any HTTP service on this port; the broker forwards <verb> <path> straight through to it. Give a command (process) or image (docker)."
        default:
            return "Give a command (process) or an image (docker), plus the port the tool serves on."
        }
    }

    private func opEditor(_ op: EditableOp) -> some View {
        let b = opBinding(op)
        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                if type == "rest" {
                    // op IS an HTTP verb; risk + args are derived server-side, so no risk/args UI
                    Picker("", selection: b.name) {
                        Text("verb…").tag("")
                        ForEach(restVerbs, id: \.self) { Text($0).tag($0) }
                    }.labelsHidden().frame(width: 120)
                    Spacer()
                } else {
                    TextField("operation name", text: b.name)
                    Picker("", selection: b.risk) { ForEach(risks, id: \.self) { Text($0).tag($0) } }
                        .labelsHidden().frame(width: 96)
                }
                Button(role: .destructive) { operations.removeAll { $0.id == op.id } } label: { Image(systemName: "trash") }
                    .buttonStyle(.borderless)
            }
            TextField("description (optional)", text: b.description).font(.caption)
            if type != "rest" {
                ForEach(op.args) { arg in argEditor(op: op, arg: arg) }
                Button { b.wrappedValue.args.append(EditableArg()) } label: { Label("Add argument", systemImage: "plus") }
                    .font(.caption2)
            }
        }
        .padding(.vertical, 3)
    }

    private func argEditor(op: EditableOp, arg: EditableArg) -> some View {
        let a = argBinding(op: op, arg: arg)
        return HStack(spacing: 6) {
            Image(systemName: "arrow.turn.down.right").font(.caption2).foregroundStyle(.secondary)
            TextField("arg name", text: a.name).font(.caption)
            Picker("", selection: a.type) { ForEach(argTypes, id: \.self) { Text($0).tag($0) } }
                .labelsHidden().frame(width: 96)
            Toggle("required", isOn: a.required).toggleStyle(.checkbox).font(.caption2).fixedSize()
            Button(role: .destructive) { removeArg(op: op, arg: arg) } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless)
        }
    }

    private func secretEditor(_ sec: EditableSecret) -> some View {
        let b = secretBinding(sec)
        return HStack(spacing: 6) {
            TextField("name (file)", text: b.name)
            TextField("field (backend key)", text: b.field)
            Toggle("writable", isOn: b.writable).toggleStyle(.checkbox).fixedSize()
            Button(role: .destructive) { secrets.removeAll { $0.id == sec.id } } label: { Image(systemName: "trash") }
                .buttonStyle(.borderless)
        }
    }

    // id-keyed bindings (safe as rows are added/removed; no array-index reliance)
    private func opBinding(_ op: EditableOp) -> Binding<EditableOp> {
        Binding(get: { operations.first { $0.id == op.id } ?? op },
                set: { v in if let i = operations.firstIndex(where: { $0.id == op.id }) { operations[i] = v } })
    }
    private func argBinding(op: EditableOp, arg: EditableArg) -> Binding<EditableArg> {
        Binding(
            get: { operations.first { $0.id == op.id }?.args.first { $0.id == arg.id } ?? arg },
            set: { v in
                guard let oi = operations.firstIndex(where: { $0.id == op.id }),
                      let ai = operations[oi].args.firstIndex(where: { $0.id == arg.id }) else { return }
                operations[oi].args[ai] = v
            })
    }
    private func removeArg(op: EditableOp, arg: EditableArg) {
        guard let oi = operations.firstIndex(where: { $0.id == op.id }) else { return }
        operations[oi].args.removeAll { $0.id == arg.id }
    }
    private func secretBinding(_ sec: EditableSecret) -> Binding<EditableSecret> {
        Binding(get: { secrets.first { $0.id == sec.id } ?? sec },
                set: { v in if let i = secrets.firstIndex(where: { $0.id == sec.id }) { secrets[i] = v } })
    }

    private func create() async {
        if await model.authorTool(source: source, manifest: manifest()) { onCreated() }
        else { saveError = model.error }
    }

    /// Build the tool_authoring manifest dict the server expects (it normalizes + validates).
    private func manifest() -> [String: Any] {
        func s(_ v: String) -> String { v.trimmingCharacters(in: .whitespaces) }
        return [
            "id": s(id), "type": s(type), "description": s(description),
            "command": s(command), "image": s(image), "port": Int(s(port)) ?? 0,
            "operations": operations.compactMap { op -> [String: Any]? in
                guard !s(op.name).isEmpty else { return nil }
                return ["name": s(op.name), "risk": op.risk, "description": s(op.description),
                        "args": op.args.compactMap { a -> [String: Any]? in
                            s(a.name).isEmpty ? nil : ["name": s(a.name), "type": a.type, "required": a.required] }]
            },
            "secrets": secrets.compactMap { sec -> [String: Any]? in
                guard !s(sec.name).isEmpty else { return nil }
                var d: [String: Any] = ["name": s(sec.name), "field": s(sec.field), "writable": sec.writable]
                if !s(sec.vault).isEmpty { d["vault"] = s(sec.vault) }
                if !s(sec.item).isEmpty { d["item"] = s(sec.item) }
                return d
            },
        ]
    }
}

/// Read-only observability: recent broker requests (who called what, and its status) and the audit
/// log (operator + broker events). Both from GET /api/audit.
struct ActivityPane: View {
    @EnvironmentObject var model: AppModel
    @State private var which: Which = .requests
    enum Which: String, CaseIterable, Identifiable {
        case requests = "Requests", audit = "Audit"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Picker("", selection: $which) {
                    ForEach(Which.allCases) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented).labelsHidden().frame(maxWidth: 220)
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                Button { Task { await model.refreshAudit() } } label: { Image(systemName: "arrow.clockwise") }
                    .help("Refresh")
            }
            if which == .requests { requestsTable } else { auditTable }
        }
        .padding()
        .navigationTitle("Activity")
        .task { await model.refreshAudit() }
    }

    @ViewBuilder private var requestsTable: some View {
        let rows = model.audit?.requests ?? []
        if rows.isEmpty {
            emptyState("No requests yet", "Caller tool calls appear here once the broker handles them.")
        } else {
            Table(rows) {
                TableColumn("#") { Text(verbatim: "\($0.id)") }.width(44)
                TableColumn("Caller") { Text(callerName($0.callerId)) }
                TableColumn("Operation") { Text(verbatim: "\($0.tool).\($0.op)") }
                TableColumn("Status") { r in Text(r.status).foregroundStyle(color(r.status)) }
                TableColumn("When") { Text(Self.when($0.createdAt)) }.width(150)
            }
        }
    }

    @ViewBuilder private var auditTable: some View {
        let rows = model.audit?.audit ?? []
        if rows.isEmpty {
            emptyState("No audit events yet", "Operator and broker actions are recorded here.")
        } else {
            Table(rows) {
                TableColumn("When") { Text(Self.when($0.at)) }.width(150)
                TableColumn("Event") { Text(verbatim: "\($0.component).\($0.eventType)") }
                TableColumn("Outcome") { e in Text(e.outcome).foregroundStyle(color(e.outcome)) }
                TableColumn("Req") { Text(verbatim: $0.requestId.map { "\($0)" } ?? "—") }.width(50)
                TableColumn("Details") {
                    Text($0.details?.compact ?? "").font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func emptyState(_ title: String, _ sub: String) -> some View {
        VStack(spacing: 6) {
            Image(systemName: "tray").font(.largeTitle).foregroundStyle(.secondary)
            Text(title).foregroundStyle(.secondary)
            Text(sub).font(.caption).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func callerName(_ id: Int) -> String {
        model.callers.first { $0.id == id }?.name ?? "#\(id)"
    }

    // green = allowed/done, red = denied/failed, orange = pending — others neutral.
    private func color(_ word: String) -> Color {
        switch word {
        case "completed", "allowed", "ok", "success": return .green
        case "denied", "failed", "error", "rejected": return .red
        case "pending", "review": return .orange
        default: return .primary
        }
    }

    private static let fmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "MMM d, HH:mm:ss"; return f
    }()
    private static func when(_ epoch: Double) -> String {
        fmt.string(from: Date(timeIntervalSince1970: epoch))
    }
}

/// Editable broker settings (broker.toml). The nod token is write-only — blank keeps the stored
/// one. Changes need a broker restart to take effect.
struct ConfigPane: View {
    @EnvironmentObject var model: AppModel
    @State private var loaded = false
    @State private var port = ""
    @State private var toolsRoot = ""
    @State private var nodURL = ""
    @State private var nodChannel = ""
    @State private var nodToken = ""
    @State private var nodTokenIsSet = false

    @State private var approvalTTL = ""
    @State private var rateLimit = ""

    var body: some View {
        Form {
            Section("Approval surface (nod)") {
                TextField("nod URL", text: $nodURL).autocorrectionDisabled()
                TextField("nod channel", text: $nodChannel).autocorrectionDisabled()
                SecureField(nodTokenIsSet ? "nod token — set (blank keeps it)" : "nod token", text: $nodToken)
            }
            Section("Limits") {
                TextField("Approval TTL (seconds)", text: $approvalTTL)
                TextField("Rate limit (per caller/min, 0 = off)", text: $rateLimit)
            }
            Section("Discovery") {
                TextField("Tools root", text: $toolsRoot).autocorrectionDisabled()
                TextField("Broker port", text: $port)
            }
            Section {
                Button("Save") { Task { await save() } }.disabled(!loaded || model.busy)
                Text("Restart the broker (sidebar ↻) to apply.").font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Config")
        .task { await load() }
    }

    private func load() async {
        await model.refreshConfig()
        if let c = model.config {
            port = String(c.port); toolsRoot = c.toolsRoot
            nodURL = c.nodUrl; nodChannel = c.nodChannel
            approvalTTL = String(c.approvalTtl); rateLimit = String(c.rateLimit)
            nodTokenIsSet = c.nodTokenSet; nodToken = ""
        }
        loaded = true
    }

    private func save() async {
        await model.saveConfig(
            port: Int(port) ?? model.config?.port ?? 8765,
            toolsRoot: toolsRoot,
            nodURL: nodURL, nodChannel: nodChannel,
            nodToken: nodToken.isEmpty ? nil : nodToken,
            approvalTTL: Int(approvalTTL) ?? model.config?.approvalTtl ?? 3600,
            rateLimit: Int(rateLimit) ?? model.config?.rateLimit ?? 120)
        nodToken = ""
        nodTokenIsSet = model.config?.nodTokenSet ?? nodTokenIsSet
    }
}
