import Foundation

public enum EnabledToolsMerge {
    public static func reconcile(baseline: Set<String>, local: Set<String>, remote: Set<String>) -> Set<String> {
        remote.union(local.subtracting(baseline)).subtracting(baseline.subtracting(local))
    }
}
