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

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct ToolstackApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("Toolstack") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 760, minHeight: 520)
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if model.authenticated {
                OperatorView()
            } else {
                LoginView()
            }
        }
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
        NavigationSplitView {
            List {
                Section("Broker") { BrokerPane() }
            }
            .navigationTitle("Toolstack")
        } detail: {
            TabView {
                CallersPane().tabItem { Label("Callers", systemImage: "person.2") }
                ToolsPane().tabItem { Label("Tools", systemImage: "wrench.and.screwdriver") }
                ConfigPane().tabItem { Label("Config", systemImage: "gearshape") }
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Sign Out") { Task { await model.logout() } }
            }
        }
        .task { await model.refreshAll() }
    }
}

struct BrokerPane: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        let running = model.broker?.running == true
        HStack(spacing: 7) {
            Circle().fill(running ? .green : .secondary).frame(width: 9, height: 9)
            Text(running ? "running" : "stopped").font(.callout)
            if let port = model.broker?.port {
                Text(verbatim: ":\(port)").font(.caption).foregroundStyle(.secondary)  // no thousands separator
            }
            Spacer(minLength: 0)
        }
        // Compact icon controls — the sidebar is too narrow for "Start/Stop/Restart" labels
        // (they truncated to "St…"). Tooltips name each on hover.
        HStack(spacing: 6) {
            control("play.fill", "Start broker", disabled: running)  { await model.brokerAction("start") }
            control("stop.fill", "Stop broker", disabled: !running)  { await model.brokerAction("stop") }
            control("arrow.clockwise", "Restart broker", disabled: false) { await model.brokerAction("restart") }
        }
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
            if let banner = model.banner {
                Text(banner).font(.callout.monospaced())
                    .padding(10).background(.green.opacity(0.15), in: .rect(cornerRadius: 8))
                    .textSelection(.enabled)
            }
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
    @State private var importing = false

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
                        }
                        .padding(.vertical, 2)
                        if !tool.ops.isEmpty {
                            Divider().padding(.vertical, 2)
                            Text("Operations").font(.caption.bold()).foregroundStyle(.secondary)
                            ForEach(tool.ops) { op in opRow(op) }
                        }
                        Divider().padding(.vertical, 2)
                        Text("Secrets").font(.caption.bold()).foregroundStyle(.secondary)
                        if tool.secrets.isEmpty {
                            Text("No secrets declared.").font(.caption).foregroundStyle(.secondary)
                        } else {
                            ForEach(tool.secrets) { secretRow($0) }
                        }
                    } label: {
                        HStack {
                            Circle().fill(tool.running ? .green : .secondary).frame(width: 8, height: 8)
                            Text(tool.id).bold()
                            Text(tool.type).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .navigationTitle("Tools")
        .sheet(item: $editing) { tool in
            ToolEditor(tool: tool).environmentObject(model)
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.folder]) { result in
            if case .success(let url) = result {
                Task { await model.addTool(source: url.path) }
            }
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
            Button { importing = true } label: { Label("Add tool", systemImage: "plus") }
        }
        .padding(.horizontal).padding(.vertical, 8)
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

/// Per-caller policy editor: an allow / review / deny picker for every op of the caller's
/// ENABLED tools (enable tools via the caller menu first). "deny" just means the op isn't in the
/// allow or review list (that's how the broker stores it).
struct PolicyEditor: View {
    @EnvironmentObject var model: AppModel
    let caller: String
    @Environment(\.dismiss) private var dismiss
    @State private var effects: [String: Effect] = [:]   // "tool.op" -> effect
    @State private var enabled: Set<String> = []         // tools this caller is enabled for
    @State private var loaded = false

    private var enabledTools: [ToolInfo] { model.tools.filter { enabled.contains($0.id) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Policy — \(caller)").font(.title2.bold())
                Spacer()
                Button("Allow all") { setAll(.allow) }.disabled(!loaded || enabledTools.isEmpty)
                Button("Deny all") { setAll(.deny) }.disabled(!loaded || enabledTools.isEmpty)
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
                            ForEach(tool.ops) { op in
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
        .frame(minWidth: 520, minHeight: 460)
        .task { await load() }
    }

    private func bind(_ key: String) -> Binding<Effect> {
        Binding(get: { effects[key] ?? .deny }, set: { effects[key] = $0 })
    }

    private func setAll(_ effect: Effect) {
        for key in Array(effects.keys) { effects[key] = effect }
    }

    private func load() async {
        await model.refreshTools()
        guard let resp = await model.loadPolicy(for: caller) else { loaded = true; return }
        enabled = Set(resp.enabled)
        var current: [String: Effect] = [:]
        for tool in enabledTools {
            for op in tool.ops { current["\(tool.id).\(op.op)"] = resp.policy.effect(tool: tool.id, op: op.op) }
        }
        effects = current
        loaded = true
    }

    private func save() async {
        let allow = effects.filter { $0.value == .allow }.map(\.key)
        let review = effects.filter { $0.value == .review }.map(\.key)
        await model.savePolicy(caller: caller, allow: allow, review: review)
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
