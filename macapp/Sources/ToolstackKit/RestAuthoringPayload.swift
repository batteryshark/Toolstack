import Foundation

/// Existing admin authoring contract. Header templates are call hints, never stored credentials.
public enum RestAuthoringPayload {
    public static func operation(name: String, verb: String, path: String, description: String,
                                 bodyKind: String, allowedHeaders: [String]) -> [String: Any] {
        var row: [String: Any] = ["name": name, "verb": verb, "path": path,
                                  "description": description, "body_kind": bodyKind]
        if !allowedHeaders.isEmpty { row["allowed_headers"] = allowedHeaders }
        return row
    }
}
