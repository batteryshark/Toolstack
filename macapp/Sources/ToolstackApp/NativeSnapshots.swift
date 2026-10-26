import AppKit
import SwiftUI
import ToolstackKit

/// Offscreen, fake-only product view rendering; never enters the application's scene lifecycle.
@MainActor enum NativeSnapshots {
    static func run(directory: String) {
        NSApplication.shared.setActivationPolicy(.prohibited)
        do {
            if CommandLine.arguments.contains("--settings-snapshots") {
                try settings(directory: directory)
                return
            }
            let model = AppModel()
            let decoder = JSONDecoder()
            model.tools = try decoder.decode(ToolsResponse.self, from: Data(#"{"tools":[{"id":"notes-demo","type":"api","running":true,"alive":false,"state":"crashed","health":"stopped","ops":[{"op":"read_note","risk":"read","description":"Read a note"},{"op":"write_note","risk":"write","description":"Write a note"}]}]}"#.utf8)).tools
            let response = try decoder.decode(PolicyResponse.self, from: Data(#"{"name":"writer-demo","enabled":["notes-demo"],"policy":{"tools":{"notes-demo":{"read_note":"allow"}}}}"#.utf8))
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            let contracts = CommandLine.arguments.contains("--contract-snapshots")
            let states = contracts ? ["added", "registration-unknown", "unregister-unknown"] : ["load-failed", "save-rejected", "save-unknown", "draft", "recovery", "recovery-unknown"]
            for state in states {
                model.uncertainMutation = state == "recovery-unknown" ? "Restart notes-demo: outcome unknown" : nil
                if contracts {
                    let alive = state != "added"
                    model.tools = try decoder.decode(ToolsResponse.self, from: Data("{\"tools\":[{\"id\":\"notes-demo\",\"running\":\(alive),\"alive\":\(alive),\"removable\":true,\"path\":\"/fake/notes-demo\"}]}".utf8)).tools
                    model.continuationTarget = state == "unregister-unknown" ? nil : "notes-demo"
                    if state == "unregister-unknown" { model.uncertainMutation = "Unregister notes-demo: outcome unknown. Filesystem outcome unknown." }
                }
                var draft = PolicyDraft(caller: "writer-demo")
                if state == "load-failed" { draft.loadFailed() }
                else {
                    draft.load(response)
                    draft.set(.review, for: "notes-demo.write_note")
                    if state != "draft" {
                        _ = draft.beginSave()
                        draft.failed(state == "save-rejected" ? ApiError.http(status: 400, message: "fixture validation") : ApiError.transport("fixture timeout"))
                    }
                }
                for width in [1440, 1100] {
                    let surface = contracts || state.hasPrefix("recovery") ? AnyView(OperatorView(selection: 1)) : AnyView(PolicyEditor(caller: "writer-demo", fixture: draft))
                    let view = surface
                        .environmentObject(model).environment(\.colorScheme, .light)
                        .environment(\.controlActiveState, .active)
                        .frame(width: CGFloat(width), height: 900)
                        .background(Color(nsColor: .windowBackgroundColor))
                    let host = NSHostingView(rootView: view)
                    host.frame = NSRect(x: 0, y: 0, width: width, height: 900)
                    let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
                    window.appearance = NSAppearance(named: .aqua)
                    window.contentView = host
                    host.layoutSubtreeIfNeeded()
                    RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.15))
                    host.layoutSubtreeIfNeeded()
                    guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { throw SnapshotError.render }
                    host.cacheDisplay(in: host.bounds, to: bitmap)
                    guard let png = bitmap.representation(using: .png, properties: [:]) else { throw SnapshotError.render }
                    try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent("\(state)-\(width).png"))
                    func geometry(_ view: NSView) -> [[String: String]] {
                        [["class": String(describing: type(of: view)), "frame": NSStringFromRect(view.convert(view.bounds, to: host))]] + view.subviews.flatMap(geometry)
                    }
                    let data = try JSONSerialization.data(withJSONObject: geometry(host), options: [.prettyPrinted, .sortedKeys])
                    try data.write(to: URL(fileURLWithPath: directory).appendingPathComponent("\(state)-\(width)-geometry.json"))
                }
            }
            print("Rendered \(states.count * 2) offscreen SwiftUI views with NSView geometry; no live focus or VoiceOver assertion.")
        } catch { fputs("Snapshot failure: \(error)\n", stderr); exit(1) }
    }
    enum SnapshotError: Error { case render }

    private static func settings(directory: String) throws {
        let catalog = Dictionary(uniqueKeysWithValues: (0..<30).map { tool in
            (String(format: "tool%02d", tool), (0..<20).map { op in
                ["op": String(format: "fn%02d", op), "risk": "read", "description": "Fake function"]
            })
        })
        let payload: [String: Any] = ["name": "writer-demo", "caller_id": 1, "operator": "fake-admin", "installation": "fake-installation", "revision": "one",
                                     "enabled": ["tool00"], "policy": ["tools": ["tool00": ["fn01": "review"]]], "catalog": catalog]
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        let snapshot = try decoder.decode(SettingsSnapshot.self, from: JSONSerialization.data(withJSONObject: payload))
        let model = AppModel()
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        var evidence: [[String: Any]] = []
        for state in ["enabled", "policy", "many", "empty", "stale"] {
            var draft = CallerSettingsDraft(snapshot)
            draft.expanded = ["tool00"]
            draft.setFunction("tool00", "fn02", enabled: false)
            draft.values.tools["tool00"]?["fn03"] = "review"
            if state != "enabled" { draft.tab = "policy" }
            if state == "many" { draft.search = "fn01" }
            if state == "empty" { draft.search = "no-such-function" }
            if state == "stale" { draft.phase = .stale }
            for width in [900, 660] {
                let host = NSHostingView(rootView: CallerSettingsEditor(caller: "writer-demo", fixture: draft)
                    .environmentObject(model).environment(\.colorScheme, .light).environment(\.controlActiveState, .active)
                    .frame(width: CGFloat(width), height: 680).background(Color(nsColor: .windowBackgroundColor)))
                host.frame = NSRect(x: 0, y: 0, width: width, height: 680)
                let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
                window.isReleasedWhenClosed = false; window.appearance = NSAppearance(named: .aqua); window.contentView = host
                host.layoutSubtreeIfNeeded(); RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.2)); host.layoutSubtreeIfNeeded()
                guard !window.isVisible, NSApplication.shared.activationPolicy() == .prohibited,
                      let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { throw SnapshotError.render }
                host.cacheDisplay(in: host.bounds, to: bitmap)
                guard let png = bitmap.representation(using: .png, properties: [:]) else { throw SnapshotError.render }
                try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent("settings-\(state)-\(width).png"))
                evidence.append(["state": state, "width": width, "functions": 600, "tools": 30, "window_visible": window.isVisible,
                                 "activation_prohibited": true, "live_keyboard_or_voiceover": false])
                window.close()
            }
        }
        try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
            .write(to: URL(fileURLWithPath: directory).appendingPathComponent("settings-evidence.json"))
        print("Rendered 10 native caller-settings fixtures offscreen; live keyboard and VoiceOver remain separate checks.")
    }
}
