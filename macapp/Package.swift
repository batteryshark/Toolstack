// swift-tools-version: 5.9
import PackageDescription

// Toolstack native operator app (macOS). `ToolstackKit` is the testable core (API client +
// models — Foundation only, no SwiftUI), so `swift test` runs headlessly. `ToolstackApp` is the
// SwiftUI window. Open this package in Xcode (File ▸ Open ▸ macapp/Package.swift) and run the
// "ToolstackApp" target, or `swift run ToolstackApp`. See README.md.
let package = Package(
    name: "Toolstack",
    platforms: [.macOS(.v13)],
    targets: [
        .target(name: "ToolstackKit"),
        .executableTarget(name: "ToolstackApp", dependencies: ["ToolstackKit"],
                          resources: [.copy("Resources/MenuBarIcon.png")]),
        .testTarget(name: "ToolstackKitTests", dependencies: ["ToolstackKit"]),
    ]
)
