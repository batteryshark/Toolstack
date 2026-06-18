import SwiftUI
import ToolstackKit

@main
struct ToolstackApp: App {
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
            Text("Sign in to the admin").foregroundStyle(.secondary)
            SecureField("Admin password", text: $password)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
                .onSubmit { submit() }
            Button("Sign In", action: submit)
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || model.busy)
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
        HStack {
            Circle().fill(running ? .green : .secondary).frame(width: 10, height: 10)
            Text(running ? "running" : "stopped")
            if let port = model.broker?.port { Text("· :\(port)").foregroundStyle(.secondary) }
        }
        HStack {
            Button("Start") { Task { await model.brokerAction("start") } }.disabled(running || model.busy)
            Button("Stop") { Task { await model.brokerAction("stop") } }.disabled(!running || model.busy)
            Button("Restart") { Task { await model.brokerAction("restart") } }.disabled(model.busy)
        }
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
