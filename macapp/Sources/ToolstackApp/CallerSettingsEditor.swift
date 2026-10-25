import SwiftUI
import ToolstackKit

/// The same two-tab editor as the web/desktop surface, using native controls.
struct CallerSettingsEditor: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let caller: String
    @State private var draft: CallerSettingsDraft?
    @State private var comparison: SettingsSnapshot?
    @State private var message: String?
    @State private var storageError = false
    @State private var loading = false
    @State private var leaving = false
    @State private var epoch: UUID?
    @State private var account = ""
    @FocusState private var searchFocused: Bool

    init(caller: String, fixture: CallerSettingsDraft? = nil) {
        self.caller = caller; _draft = State(initialValue: fixture)
    }

    private var store: SettingsDraftStore {
        SettingsDraftStore(directory: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Toolstack/CallerSettings", isDirectory: true))
    }
    private var saving: Bool { draft?.phase == .saving }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Caller settings · \(caller)").font(.title2.bold())
            if let message { Text(message).font(.callout).foregroundStyle(.secondary).accessibilityLabel(message) }
            if let current = draft {
                editor(current)
            } else {
                if loading { ProgressView("Loading settings…") }
                else { Button("Retry load") { Task { await load() } }.buttonStyle(.borderedProminent) }
                Spacer()
            }
            HStack(spacing: 20) {
                Text(saving ? "Saving both tabs…" : draft?.dirty == true ? "Unsaved changes · Both tabs · \(storageError ? "Not stored" : "Draft kept on this device")" : "No unsaved changes")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer()
                Button("Cancel") { leave() }.keyboardShortcut(.cancelAction).disabled(saving)
                Button("Save changes") { Task { await save() } }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(draft?.canSave != true || loading || model.busy || model.effectInFlight || model.uncertainMutation != nil)
            }
        }
        .padding(20).frame(minWidth: 620, idealWidth: 820, maxWidth: 960, minHeight: 480, idealHeight: 620, maxHeight: 780)
        .controlSize(.large).tint(.blue)
        .background(Color(red: 246.0/255, green: 247.0/255, blue: 249.0/255))
        .environment(\.colorScheme, .light)
        .accessibilityLabel("Caller settings for \(caller)")
        .interactiveDismissDisabled(draft?.dirty == true || saving || draft?.phase == .unknown)
        .task {
            if CommandLine.arguments.contains("--snapshot-directory") { return }
            await load()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(20))
                if Task.isCancelled { return }
                await observe()
            }
        }
        .onChange(of: model.generation) { _ in dismiss() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in Task { await observe() } }
        .confirmationDialog("Leave settings for \(caller)?", isPresented: $leaving) {
            Button("Stay", role: .cancel) {}
            Button("Keep draft and close") { if persist() { dismiss() } }.disabled(storageError)
            Button("Discard draft", role: .destructive) {
                guard let draft else { dismiss(); return }
                do { try store.discard(account: account, snapshot: draft.snapshot); dismiss() }
                catch { message = "Could not discard the stored draft. Keep this window open and retry." }
            }
        } message: {
            Text("Both tabs are kept together. A save with an unknown outcome may already have applied; discarding does not undo it.")
        }
        .sheet(isPresented: Binding(get: { comparison != nil }, set: { if !$0 { comparison = nil } })) {
            if let latest = comparison, let draft { comparisonView(draft, latest) }
        }
    }

    private func editor(_ current: CallerSettingsDraft) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("Settings tab", selection: binding(\.tab)) {
                Text("Enabled tools" + (current.values.enabled != current.baseline.enabled || current.values.excluded != current.baseline.excluded ? " · Unsaved changes" : "")).tag("enabled")
                Text("Policy" + (current.values.tools != current.baseline.tools ? " · Unsaved changes" : "")).tag("policy")
            }.pickerStyle(.segmented)
            HStack {
                TextField("Search tools and functions", text: Binding(get: { draft?.search ?? "" }, set: { query in edit { $0.search = query; $0.collapsedSearch.removeAll() } })).textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Search tools and functions").focused($searchFocused)
                Toggle("Enabled only", isOn: binding(\.enabledOnly))
                Toggle("Needs review", isOn: binding(\.needsReview))
            }
            let tools = current.snapshot.catalog.keys.sorted().filter { !current.matches($0).isEmpty }
            Text("\(tools.reduce(0) { $0 + current.matches($1).count }) of \(current.snapshot.catalog.values.reduce(0) { $0 + $1.count }) functions · \(tools.count) tools")
                .font(.callout).foregroundStyle(.secondary)
            if current.phase == .stale || current.phase == .unknown {
                HStack {
                    Text(current.phase == .unknown ? "Save outcome unknown · Draft retained" : "Changed elsewhere · Draft retained")
                    Spacer()
                    Button("Compare latest") { Task { await compare() } }.disabled(loading)
                }.padding(10).background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
            }
            // Keep both scroll views alive so each tab retains its scroll position.
            ZStack {
                ForEach(["enabled", "policy"], id: \.self) { tab in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            if tools.isEmpty {
                                Text("No matching functions.").padding()
                                Button("Clear filters") { edit { $0.search = ""; $0.enabledOnly = false; $0.needsReview = false }; searchFocused = true }.padding()
                            }
                            ForEach(tools, id: \.self) { tool in group(current, tool, tab) }
                        }
                    }.opacity(current.tab == tab ? 1 : 0)
                        .allowsHitTesting(current.tab == tab).disabled(current.tab != tab || saving)
                        .accessibilityHidden(current.tab != tab)
                }
            }.background(Color.white, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.gray.opacity(0.25)))
            Text(current.filtering ? "All / None affect visible filtered matches only." : "All / None affect the whole tool. Enabling never grants Allow.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func group(_ current: CallerSettingsDraft, _ tool: String, _ tab: String) -> some View {
        let ops = current.matches(tool)
        let all = current.snapshot.catalog[tool, default: []]
        let count = all.filter { current.values.active(tool, $0.op) }.count
        let expanded = current.expanded.contains(tool) || current.filtering && !current.collapsedSearch.contains(tool)
        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                Button {
                    edit {
                        if expanded { $0.expanded.remove(tool); $0.collapsedSearch.insert(tool) }
                        else { $0.expanded.insert(tool); $0.collapsedSearch.remove(tool) }
                    }
                } label: { Label(tool, systemImage: expanded ? "chevron.down" : "chevron.right").fontWeight(.semibold).frame(minHeight: 32).contentShape(Rectangle()) }
                    .buttonStyle(.plain).accessibilityLabel("\(tool) functions")
                    .accessibilityValue(expanded ? "Expanded" : "Collapsed")
                Text("\(count)/\(all.count) enabled" + (current.filtering ? " · \(ops.count) matches" : ""))
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                if tab == "enabled" {
                    Toggle("Whole tool", isOn: Binding(get: { count == all.count }, set: { enabled in
                        edit { $0.setTool(tool, enabled: enabled) }; if draft?.matches(tool).isEmpty == true { searchFocused = true }
                    }))
                        .accessibilityLabel("Enable whole tool \(tool)")
                    Button(current.filtering ? "All matches" : "All") { edit { $0.bulk(tool, enabled: true) }; if draft?.matches(tool).isEmpty == true { searchFocused = true } }
                        .accessibilityLabel("Enable \(current.filtering ? "matched" : "all") \(tool) functions")
                    Button(current.filtering ? "None matches" : "None") { edit { $0.bulk(tool, enabled: false) }; if draft?.matches(tool).isEmpty == true { searchFocused = true } }
                        .accessibilityLabel("Disable \(current.filtering ? "matched" : "all") \(tool) functions")
                }
            }
            if expanded {
                ForEach(ops) { op in function(current, tool, op, tab) }
            }
            Divider()
        }.padding(10)
    }

    private func function(_ current: CallerSettingsDraft, _ tool: String, _ op: OpInfo, _ tab: String) -> some View {
        HStack {
            if tab == "enabled" {
                Toggle(op.op, isOn: Binding(get: { current.values.active(tool, op.op) }, set: { enabled in
                    edit { $0.setFunction(tool, op.op, enabled: enabled) }
                    if draft?.matches(tool).contains(where: { $0.op == op.op }) == false { searchFocused = true }
                })).accessibilityLabel("Enable \(tool) / \(op.op)")
                Spacer()
                Text(current.values.effect(tool, op.op).capitalized).font(.caption).foregroundStyle(.secondary)
            } else {
                Text(op.op)
                if !current.values.active(tool, op.op) { Text("Disabled").font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Picker("Policy for \(tool) / \(op.op)", selection: Binding(get: { current.values.effect(tool, op.op) }, set: { effect in
                    edit { $0.values.tools[tool]?[op.op] = effect }
                    if draft?.matches(tool).contains(where: { $0.op == op.op }) == false { searchFocused = true }
                })) {
                    Text("Deny").tag("deny"); Text("Review").tag("review"); Text("Allow").tag("allow")
                }.labelsHidden().frame(width: 125)
            }
        }.padding(.leading, 20).frame(minHeight: 32)
    }

    private func comparisonView(_ current: CallerSettingsDraft, _ latest: SettingsSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Compare · \(caller)").font(.title2.bold())
            Text("Your draft is unchanged. Keep only your explicit edits on the latest settings, or Stay.")
            HStack { Text("Setting").frame(maxWidth: .infinity, alignment: .leading); Text("Your draft").frame(width: 180); Text("Latest saved").frame(width: 180) }.font(.headline)
            ScrollView {
                LazyVStack {
                    let rows = current.differences(latest)
                    if rows.isEmpty { Text("Both tabs match the saved settings. No write is needed.") }
                    ForEach(rows) { row in
                        HStack { Text(row.id).frame(maxWidth: .infinity, alignment: .leading); Text(row.draft).frame(width: 180); Text(row.latest).frame(width: 180) }
                            .padding(.vertical, 4)
                        Divider()
                    }
                }
            }
            if !current.canRebase(latest) { Text("The function set or server changed. Your draft is retained; discard it explicitly and reopen to edit the latest catalog.") }
            HStack(spacing: 20) {
                Spacer()
                Button("Stay") { comparison = nil }.keyboardShortcut(.cancelAction)
                Button("Keep my edits on latest") { edit { _ = $0.keepEdits(on: latest) }; comparison = nil }
                    .buttonStyle(.borderedProminent).disabled(!current.canRebase(latest))
            }
        }.padding(20).frame(width: 760, height: 500)
    }

    private func binding<T>(_ key: WritableKeyPath<CallerSettingsDraft, T>) -> Binding<T> {
        Binding(get: { draft![keyPath: key] }, set: { value in edit { $0[keyPath: key] = value } })
    }
    private func edit(_ mutation: (inout CallerSettingsDraft) -> Void) {
        guard var value = draft, !saving else { return }
        mutation(&value); draft = value; _ = persist()
    }
    @discardableResult private func persist() -> Bool {
        guard let draft, epoch == model.generation else { return false }
        do { try store.save(draft, account: account); storageError = false; return true }
        catch { storageError = true; message = "Draft storage unavailable. Keep this window open or save before quitting."; return false }
    }
    private func leave() { if draft?.dirty == true || draft?.phase == .unknown { leaving = true } else { dismiss() } }
    private func load() async {
        epoch = model.generation; account = model.serverURL; loading = true; message = nil
        defer { loading = false }
        do {
            let latest = try await model.loadCallerSettings(caller)
            guard epoch == model.generation else { return }
            draft = try store.load(account: account, snapshot: latest) ?? CallerSettingsDraft(latest)
            if draft?.dirty == true { message = "Resume settings draft · \(caller)" }
        } catch { message = "Settings unavailable. Your stored drafts have not been changed. Retry load." }
    }
    private func observe() async {
        guard draft != nil, !saving, !loading, epoch == model.generation else { return }
        do {
            let latest = try await model.loadCallerSettings(caller)
            guard epoch == model.generation, !saving else { return }
            draft?.observe(latest); _ = persist()
        } catch { guard epoch == model.generation else { return }; if draft?.phase != .unknown { draft?.phase = .stale }; message = "Latest settings unavailable · Draft retained"; _ = persist() }
    }
    private func compare() async {
        guard !saving else { return }; loading = true
        defer { loading = false }
        do {
            let latest = try await model.loadCallerSettings(caller)
            guard epoch == model.generation else { return }
            comparison = latest
        } catch { message = "Comparison unavailable · Draft retained. Sign in if needed, then retry." }
    }
    private func save() async {
        guard var pending = draft, pending.canSave else { return }
        draft?.phase = .saving; _ = persist()
        pending = await model.writeCallerSettings(pending)
        guard epoch == model.generation else { return }
        draft = pending
        if pending.phase == .saved { if persist() { dismiss() } }
        else { _ = persist() }
    }
}
