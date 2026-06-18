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
            CallersPane()
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
                        Button("Revoke", role: .destructive) {
                            // wired in T-031 alongside the rest of the caller-management UI
                        }.disabled(true)
                    }
                }
            }
        }
        .padding()
        .navigationTitle("Callers")
    }
}
