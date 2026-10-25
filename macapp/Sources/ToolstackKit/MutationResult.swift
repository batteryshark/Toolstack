import Foundation

public enum MutationResult: Equatable, Sendable {
    case success, rejected, unknown
    public init(error: Error) {
        switch error {
        case ApiError.unauthorized: self = .rejected
        case ApiError.http(let status, _) where [400, 401, 403, 404, 405, 422].contains(status): self = .rejected
        default: self = .unknown
        }
    }
}
