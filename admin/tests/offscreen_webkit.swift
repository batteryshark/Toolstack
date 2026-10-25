// Finite, unshown WKWebView proof runner. No activation or persistent website data.
import AppKit
import WebKit

struct Fixture: Decodable { let name: String; let html: String; let width: Int; let height: Int }

final class Runner: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    let fixtures: [Fixture]
    let output: URL
    var index = 0
    var window: NSWindow?
    var view: WKWebView?
    var timer: Timer?
    var completed = false
    var initialNavigation = true
    var results: [[String: Any]] = []
    let started = Date()
    var policy: [String: Any] = [:]

    init(fixtures: [Fixture], output: URL) { self.fixtures = fixtures; self.output = output }

    func start() {
        // The parent also imposes a 120-second process deadline.
        Timer.scheduledTimer(withTimeInterval: 115, repeats: false) { _ in self.finish("total watchdog") }
        next()
    }

    func next() {
        guard index < fixtures.count else { finish(nil); return }
        completed = false
        initialNavigation = true
        let f = fixtures[index]
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: false) { _ in self.finish("case watchdog: \(f.name)") }
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        config.userContentController.add(self, name: "proof")
        // Block accidental external traffic; fixtures use only embedded fake fetch.
        let rules = """
        [{"trigger":{"url-filter":"^https?://"},"action":{"type":"block"}}]
        """
        let ruleURL = output.appendingPathComponent(".rule-store", isDirectory: true)
        do { try FileManager.default.createDirectory(at: ruleURL, withIntermediateDirectories: true) }
        catch { finish("private rule directory: \(error)"); return }
        WKContentRuleListStore(url: ruleURL).compileContentRuleList(forIdentifier: "clear-desk-offscreen", encodedContentRuleList: rules) { list, error in
            guard let list = list else { self.finish("traffic blocker: \(String(describing: error))"); return }
            config.userContentController.add(list)
            let frame = NSRect(x: 0, y: 0, width: CGFloat(f.width), height: CGFloat(f.height))
            let web = WKWebView(frame: frame, configuration: config)
            web.navigationDelegate = self
            let host = NSWindow(contentRect: frame, styleMask: [.borderless], backing: .buffered, defer: false)
            host.isReleasedWhenClosed = false
            host.contentView = web
            // Deliberately never orderFront/makeKey/activate. Window remains unshown.
            self.window = host; self.view = web
            web.loadHTMLString(f.html, baseURL: URL(string: "https://fixture.invalid/"))
        }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard !completed else { return }
        completed = true
        let f = fixtures[index]
        var result: [String: Any] = ["case": f.name, "dom": message.body, "direct_children": children(),
                                    "window_visible": window?.isVisible ?? false]
        let resultIndex = results.count
        results.append(result)
        persist(nil) // DOM evidence must survive a blocked snapshot callback.
        var snapshotFinished = false
        func completeSnapshot() {
            guard !snapshotFinished else { return }
            snapshotFinished = true
            self.results[resultIndex] = result
            self.persist(nil)
            self.timer?.invalidate()
            self.view?.configuration.userContentController.removeScriptMessageHandler(forName: "proof")
            self.view?.stopLoading(); self.window?.close(); self.view = nil; self.window = nil
            self.index += 1
            self.next()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            if !snapshotFinished { result["snapshot_error"] = "offscreen snapshot timeout"; completeSnapshot() }
        }
        let snapshot = WKSnapshotConfiguration()
        snapshot.rect = NSRect(x: 0, y: 0, width: CGFloat(f.width), height: CGFloat(f.height))
        view?.takeSnapshot(with: snapshot) { image, error in
            guard !snapshotFinished else { return }
            if let tiff = image?.tiffRepresentation,
               let bitmap = NSBitmapImageRep(data: tiff),
               let png = bitmap.representation(using: .png, properties: [:]) {
                do { try png.write(to: self.output.appendingPathComponent(f.name + ".png")); result["snapshot"] = "saved" }
                catch { result["snapshot_error"] = String(describing: error) }
            } else { result["snapshot_error"] = String(describing: error) }
            completeSnapshot()
        }
    }

    func children() -> [String] {
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axo", "pid=,ppid=,lstart=,comm="]
        process.standardOutput = pipe
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let parent = String(ProcessInfo.processInfo.processIdentifier)
            return String(decoding: data, as: UTF8.self).split(separator: "\n").compactMap { line in
                let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
                // Exclude the short-lived observation command itself.
                return fields.count > 2 && fields[1] == parent && fields[0] != String(process.processIdentifier) ? String(line) : nil
            }
        } catch { return ["child observation unavailable: \(error)"] }
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let scheme = navigationAction.request.url?.scheme
        if initialNavigation { initialNavigation = false; decisionHandler(.allow) }
        else if scheme == "about" || scheme == "data" || navigationAction.request.url == nil { decisionHandler(.allow) }
        else {
            // Record attempted destinations for interaction assertions; still never load them.
            if let url = navigationAction.request.url?.absoluteString,
               let data = try? JSONSerialization.data(withJSONObject: [url]),
               let json = String(data: data, encoding: .utf8) {
                webView.evaluateJavaScript("(window.fixtureNavigations ||= []).push(\(json)[0])", completionHandler: nil)
            }
            decisionHandler(.cancel)
        } // no backend or real navigation allowed
    }

    func finish(_ error: String?) {
        timer?.invalidate()
        view?.stopLoading(); window?.close()
        persist(error)
        exit(error == nil ? 0 : 2)
    }

    func persist(_ error: String?) {
        let report: [String: Any] = ["pid": ProcessInfo.processInfo.processIdentifier,
            "started": ISO8601DateFormatter().string(from: started),
            "activation_policy": policy, "persistent_store": false,
            "error": error as Any? ?? NSNull(), "results": results]
        if let data = try? JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: output.appendingPathComponent("webkit-results.json"))
        }
    }
}

let app = NSApplication.shared
let before = app.activationPolicy()
let requested = app.setActivationPolicy(.prohibited)
let after = app.activationPolicy()
let policy: [String: Any] = ["before": before.rawValue, "request_returned": requested,
                            "after": after.rawValue, "required": NSApplication.ActivationPolicy.prohibited.rawValue]
do {
    let manifest = URL(fileURLWithPath: CommandLine.arguments[1])
    let output = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    let fixtures = try JSONDecoder().decode([Fixture].self, from: Data(contentsOf: manifest))
    let runner = Runner(fixtures: fixtures, output: output)
    runner.policy = policy
    guard after == .prohibited else { runner.finish("Actual activation policy is not prohibited"); exit(2) }
    DispatchQueue.main.async { runner.start() }
    app.run()
    withExtendedLifetime(runner) {}
} catch { fputs("\(error)\n", stderr); exit(2) }
