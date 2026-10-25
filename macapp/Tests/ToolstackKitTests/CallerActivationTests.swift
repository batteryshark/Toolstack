import XCTest
@testable import ToolstackKit

final class CallerActivationTests: XCTestCase {
    let active = Caller(id: 1, name: "writer-demo", revokedAt: nil)
    let revoked = Caller(id: 2, name: "revoked-demo", revokedAt: 1)

    func testPrimaryActionResolvesActiveCaller() {
        XCTAssertEqual(Caller.policyTarget(in: [active, revoked], selection: [1]), active)
    }

    func testRevokedMissingAndAmbiguousSelectionsDoNothing() {
        for selection: Set<Int> in [[], [2], [99], [1, 2]] {
            XCTAssertNil(Caller.policyTarget(in: [active, revoked], selection: selection))
        }
    }

    func testSelectionUsesFreshRevocationState() {
        let updated = Caller(id: active.id, name: active.name, revokedAt: 2)
        XCTAssertNil(Caller.policyTarget(in: [updated], selection: [active.id]))
    }
}
