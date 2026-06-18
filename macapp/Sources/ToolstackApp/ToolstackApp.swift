import AppKit
import SwiftUI
import ToolstackKit

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
            if let port = model.broker?.port { Text(":\(port)").font(.caption).foregroundStyle(.secondary) }
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
    @State private var editing: Caller?    // caller whose policy is being edited
    @State private var revoking: Caller?   // caller pending revoke confirmation

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

    var body: some View {
        Group {
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
                        ForEach(tool.ops) { op in
                            HStack {
                                Text(op.op).bold()
                                Text(op.risk).font(.caption2).padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(.secondary.opacity(0.15), in: .capsule)
                                Spacer()
                                Text(op.description).font(.caption).foregroundStyle(.secondary)
                            }
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
        .task { await model.refreshTools() }
    }
}

/// Per-caller policy editor: an allow / review / deny picker for every tool op. "deny" just
/// means the op isn't in the allow or review list (that's how the broker stores it).
struct PolicyEditor: View {
    @EnvironmentObject var model: AppModel
    let caller: String
    @Environment(\.dismiss) private var dismiss
    @State private var effects: [String: Effect] = [:]   // "tool.op" -> effect
    @State private var loaded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Policy — \(caller)").font(.title2.bold())
            if !loaded {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if model.tools.isEmpty {
                Text("No tools to grant. Register a tool first.")
                    .foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(model.tools) { tool in
                        Section(tool.id) {
                            ForEach(tool.ops) { op in
                                Picker(op.op, selection: bind("\(tool.id).\(op.op)")) {
                                    ForEach(Effect.allCases) { Text($0.rawValue.capitalized).tag($0) }
                                }.pickerStyle(.segmented)
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
        .frame(minWidth: 480, minHeight: 440)
        .task { await load() }
    }

    private func bind(_ key: String) -> Binding<Effect> {
        Binding(get: { effects[key] ?? .deny }, set: { effects[key] = $0 })
    }

    private func load() async {
        await model.refreshTools()
        let policy = await model.loadPolicy(for: caller) ?? Policy()
        var current: [String: Effect] = [:]
        for tool in model.tools {
            for op in tool.ops { current["\(tool.id).\(op.op)"] = policy.effect(tool: tool.id, op: op.op) }
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
