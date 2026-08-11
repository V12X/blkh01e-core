import XCTest
@testable import BlackHoleCore

final class IngestSealTests: XCTestCase {

    func testSealOpen_roundTrip() throws {
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        XCTAssertEqual(kp.publicKey.count, 32)
        XCTAssertEqual(kp.secretKey.count, 32)
        let msg = Data("conteúdo recebido pela extensão 🕳️".utf8)
        let sealed = try XCTUnwrap(IngestSeal.seal(msg, to: kp.publicKey))
        XCTAssertNotEqual(sealed, msg)
        XCTAssertEqual(IngestSeal.open(sealed, keypair: kp), msg)
    }

    func testWrongKeypair_cannotOpen() throws {
        let kp1 = try XCTUnwrap(IngestSeal.newKeypair())
        let kp2 = try XCTUnwrap(IngestSeal.newKeypair())
        let sealed = try XCTUnwrap(IngestSeal.seal(Data("x".utf8), to: kp1.publicKey))
        XCTAssertNil(IngestSeal.open(sealed, keypair: kp2), "outro par não abre")
    }

    func testTamperedSealed_fails() throws {
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        var sealed = try XCTUnwrap(IngestSeal.seal(Data("conteudo".utf8), to: kp.publicKey))
        sealed[sealed.count - 1] ^= 0xFF
        XCTAssertNil(IngestSeal.open(sealed, keypair: kp))
    }

    func testKeypairsAreUnique() throws {
        let a = try XCTUnwrap(IngestSeal.newKeypair())
        let b = try XCTUnwrap(IngestSeal.newKeypair())
        XCTAssertNotEqual(a.publicKey, b.publicKey)
        XCTAssertNotEqual(a.secretKey, b.secretKey)
    }
}
