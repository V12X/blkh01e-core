import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Formato v2 de ingestão (streaming): header selado por chave pública + chunks AEAD sob a chave de
/// conteúdo. Substitui o v1 (item inteiro em JSON+base64), que multiplicava o payload ~5–6× e matava
/// a Share Extension (~120 MB) para qualquer coisa acima de ~20 MB.
final class IngestStreamTests: XCTestCase {

    // MARK: - Header (selado para a pública)

    func testStreamHeader_roundTrip() throws {
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        let key = try XCTUnwrap(IngestSeal.newContentKey())
        let h = IngestSeal.StreamHeader(kind: 3, name: "vídeo.mov", payloadLen: 123_456, contentKey: key)
        let sealed = try XCTUnwrap(IngestSeal.sealStreamHeader(h, to: kp.publicKey))
        let opened = try XCTUnwrap(IngestSeal.openStreamHeader(sealed, keypair: kp))
        XCTAssertEqual(opened, h)
    }

    func testStreamHeader_wrongKeypair_isNil() throws {
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        let other = try XCTUnwrap(IngestSeal.newKeypair())
        let key = try XCTUnwrap(IngestSeal.newContentKey())
        let h = IngestSeal.StreamHeader(kind: 0, name: "x", payloadLen: 1, contentKey: key)
        let sealed = try XCTUnwrap(IngestSeal.sealStreamHeader(h, to: kp.publicKey))
        XCTAssertNil(IngestSeal.openStreamHeader(sealed, keypair: other),
                     "header de OUTRO cofre não abre — base da deniabilidade da inbox compartilhada")
    }

    func testStreamHeader_shortContentKey_rejected() throws {
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        let h = IngestSeal.StreamHeader(kind: 0, name: "x", payloadLen: 1, contentKey: Data(count: 31))
        XCTAssertNil(IngestSeal.sealStreamHeader(h, to: kp.publicKey))
    }

    func testStreamHeader_tamperedSealed_isNil() throws {
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        let key = try XCTUnwrap(IngestSeal.newContentKey())
        let h = IngestSeal.StreamHeader(kind: 1, name: "n", payloadLen: 10, contentKey: key)
        var sealed = try XCTUnwrap(IngestSeal.sealStreamHeader(h, to: kp.publicKey))
        sealed[sealed.count - 1] ^= 0xFF
        XCTAssertNil(IngestSeal.openStreamHeader(sealed, keypair: kp))
    }

    // MARK: - Chunks (AEAD sob a chave de conteúdo, AAD = índice)

    func testStreamChunk_roundTrip() throws {
        let key = try XCTUnwrap(IngestSeal.newContentKey())
        let chunk = Data((0..<5000).map { UInt8($0 & 0xFF) })
        let sealed = try XCTUnwrap(IngestSeal.sealStreamChunk(chunk, contentKey: key, index: 7))
        XCTAssertEqual(IngestSeal.openStreamChunk(sealed, contentKey: key, index: 7), chunk)
    }

    func testStreamChunk_wrongIndex_isNil() throws {
        let key = try XCTUnwrap(IngestSeal.newContentKey())
        let chunk = Data("bloco".utf8)
        let sealed = try XCTUnwrap(IngestSeal.sealStreamChunk(chunk, contentKey: key, index: 2))
        // AAD = índice: um chunk reordenado/duplicado não abre no índice errado.
        XCTAssertNil(IngestSeal.openStreamChunk(sealed, contentKey: key, index: 3))
    }

    func testStreamChunk_wrongKey_isNil() throws {
        let key = try XCTUnwrap(IngestSeal.newContentKey())
        let other = try XCTUnwrap(IngestSeal.newContentKey())
        let sealed = try XCTUnwrap(IngestSeal.sealStreamChunk(Data("x".utf8), contentKey: key, index: 0))
        XCTAssertNil(IngestSeal.openStreamChunk(sealed, contentKey: other, index: 0))
    }

    func testStreamChunk_tampered_isNil() throws {
        let key = try XCTUnwrap(IngestSeal.newContentKey())
        var sealed = try XCTUnwrap(IngestSeal.sealStreamChunk(Data(repeating: 9, count: 100), contentKey: key, index: 0))
        sealed[10] ^= 0x01
        XCTAssertNil(IngestSeal.openStreamChunk(sealed, contentKey: key, index: 0))
    }
}
