import Foundation

public struct CatalogObservation: Decodable, Equatable, Sendable {
    public let observationID: String?
    public let toolIDs: [String]
    public var verified: Bool { observationID != nil }
    public static let unknown = CatalogObservation(observationID: nil)
    private init(observationID: String?) { self.observationID = observationID; self.toolIDs = [] }
    enum CodingKeys: String, CodingKey { case status, observationId, toolIds }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let status = try? values.decode(String.self, forKey: .status)
        let id = try? values.decode(String.self, forKey: .observationId)
        let ids = try? values.decode([String].self, forKey: .toolIds)
        observationID = status == "verified" && ids != nil && id?.isEmpty == false && id!.unicodeScalars.allSatisfy({ CharacterSet(charactersIn: "0123456789abcdefABCDEF").contains($0) }) ? id : nil
        toolIDs = observationID != nil ? ids! : []
    }
}
