import XCTest
@testable import BlackHoleCore

/// Arquivo cifrado para enviar (imagem etc.): round-trip, adversarial, e VETOR CONGELADO do
/// formato v1 (se quebrar, arquivos já enviados não abrem — bump de versão obrigatório).
final class SecureFileTests: XCTestCase {

    // Gerado uma vez com params .testFast(), senha "senha-fixa", payload "imagem-fake-congelada-v1".
    private let frozenV1 = "QkhGMQEAAAAAAgQAAABsxYKq1xEYPDTLMo+RYLfyGyRopDT+RyY2Vwbr7GT0gfD2T1xNYjn/4Enob1uBJBG08At8N3F48y5lNJFVTFtUpNilHA=="

    // MARK: - Round-trip

    func testRoundTrip_small() throws {
        let payload = Data("conteúdo binário 🕳️".utf8)
        let sealed = try SecureFile.seal(payload, password: "combinada", params: .testFast())
        XCTAssertEqual(try SecureFile.open(sealed, password: "combinada"), payload)
    }

    func testRoundTrip_largeish() throws {
        let payload = Data((0..<200_000).map { UInt8($0 & 0xFF) })   // ~200 KB pseudo-imagem
        let sealed = try SecureFile.seal(payload, password: "pw", params: .testFast())
        XCTAssertEqual(try SecureFile.open(sealed, password: "pw"), payload)
        XCTAssertGreaterThan(sealed.count, payload.count)            // header+tag
    }

    // MARK: - Congelado

    func testOpen_frozenV1_stillOpens() throws {
        let data = Data(base64Encoded: frozenV1)!
        XCTAssertEqual(try SecureFile.open(data, password: "senha-fixa"), Data("imagem-fake-congelada-v1".utf8))
    }

    // MARK: - Falhas

    func testWrongPassword_unified() throws {
        let sealed = try SecureFile.seal(Data("x".utf8), password: "certa", params: .testFast())
        XCTAssertThrowsError(try SecureFile.open(sealed, password: "errada")) {
            XCTAssertEqual($0 as? SecureFileError, .wrongPasswordOrCorrupt)
        }
    }

    func testTamperBody_fails() throws {
        var sealed = try SecureFile.seal(Data("segredo".utf8), password: "pw", params: .testFast())
        sealed[sealed.count - 1] ^= 0xFF
        XCTAssertThrowsError(try SecureFile.open(sealed, password: "pw")) {
            XCTAssertEqual($0 as? SecureFileError, .wrongPasswordOrCorrupt)
        }
    }

    func testTamperHeaderSalt_fails() throws {
        var sealed = try SecureFile.seal(Data("segredo".utf8), password: "pw", params: .testFast())
        sealed[14] ^= 0x01
        XCTAssertThrowsError(try SecureFile.open(sealed, password: "pw")) {
            XCTAssertEqual($0 as? SecureFileError, .wrongPasswordOrCorrupt)
        }
    }

    func testBadMagic_malformed() throws {
        var sealed = try SecureFile.seal(Data("x".utf8), password: "pw", params: .testFast())
        sealed[0] = 0x58
        XCTAssertThrowsError(try SecureFile.open(sealed, password: "pw")) {
            XCTAssertEqual($0 as? SecureFileError, .malformed)
        }
    }

    func testUnknownVersion_unsupported() throws {
        var sealed = try SecureFile.seal(Data("x".utf8), password: "pw", params: .testFast())
        sealed[4] = 99
        XCTAssertThrowsError(try SecureFile.open(sealed, password: "pw")) {
            XCTAssertEqual($0 as? SecureFileError, .unsupportedVersion)
        }
    }

    func testTruncated_malformed() {
        XCTAssertThrowsError(try SecureFile.open(Data([1, 2, 3]), password: "pw")) {
            XCTAssertEqual($0 as? SecureFileError, .malformed)
        }
    }

    func testForgedKDFAboveStandard_malformed() throws {
        var sealed = try SecureFile.seal(Data("x".utf8), password: "pw", params: .testFast())
        sealed[10] = 0xFF; sealed[11] = 0xFF; sealed[12] = 0xFF; sealed[13] = 0xFF   // memLimit gigante
        XCTAssertThrowsError(try SecureFile.open(sealed, password: "pw")) {
            XCTAssertEqual($0 as? SecureFileError, .malformed)
        }
    }

    func testEmptyPassword_rejected() {
        XCTAssertThrowsError(try SecureFile.seal(Data("x".utf8), password: "", params: .testFast())) {
            XCTAssertEqual($0 as? SecureFileError, .emptyPassword)
        }
    }

    func testSeal_containsNoPlaintext() throws {
        let sealed = try SecureFile.seal(Data("SEGREDO-MARCADOR".utf8), password: "pw", params: .testFast())
        XCTAssertNil(sealed.range(of: Data("SEGREDO-MARCADOR".utf8)))
    }

    // MARK: - Modo X25519 (arquivo para um contato, remetente autenticado)

    func testX25519_roundTrip_authenticatesSender() throws {
        let (aSK, aPK) = SecureMessage.generateIdentity()   // remetente
        let (bSK, bPK) = SecureMessage.generateIdentity()   // destinatário
        let payload = Data((0..<3000).map { UInt8($0 & 0xFF) })
        let sealed = try SecureFile.seal(payload, toPublicKey: bPK, senderPrivateKey: aSK)
        let (opened, senderPK) = try SecureFile.open(sealed, recipientPrivateKey: bSK, senderCandidates: [aPK])
        XCTAssertEqual(opened, payload)
        XCTAssertEqual(senderPK, aPK)   // remetente autenticado
    }

    func testX25519_wrongRecipient_fails() throws {
        let (aSK, _) = SecureMessage.generateIdentity()
        let (_, bPK) = SecureMessage.generateIdentity()
        let (cSK, _) = SecureMessage.generateIdentity()   // outro destinatário
        let sealed = try SecureFile.seal(Data("x".utf8), toPublicKey: bPK, senderPrivateKey: aSK)
        XCTAssertThrowsError(try SecureFile.open(sealed, recipientPrivateKey: cSK, senderCandidates: [])) {
            XCTAssertEqual($0 as? SecureFileError, .wrongPasswordOrCorrupt)
        }
    }

    func testX25519_senderNotInCandidates_fails() throws {
        let (aSK, _) = SecureMessage.generateIdentity()
        let (bSK, bPK) = SecureMessage.generateIdentity()
        let (_, strangerPK) = SecureMessage.generateIdentity()
        let sealed = try SecureFile.seal(Data("x".utf8), toPublicKey: bPK, senderPrivateKey: aSK)
        XCTAssertThrowsError(try SecureFile.open(sealed, recipientPrivateKey: bSK, senderCandidates: [strangerPK])) {
            XCTAssertEqual($0 as? SecureFileError, .wrongPasswordOrCorrupt)   // não achou o remetente
        }
    }

    func testMode_routing() throws {
        let pwFile = try SecureFile.seal(Data("x".utf8), password: "pw", params: .testFast())
        let (aSK, _) = SecureMessage.generateIdentity()
        let (_, bPK) = SecureMessage.generateIdentity()
        let xFile = try SecureFile.seal(Data("x".utf8), toPublicKey: bPK, senderPrivateKey: aSK)
        XCTAssertEqual(SecureFile.mode(of: pwFile), 1)
        XCTAssertEqual(SecureFile.mode(of: xFile), 2)
        XCTAssertNil(SecureFile.mode(of: Data([1, 2, 3])))
    }

    func testCrossMode_rejected() throws {
        let (aSK, aPK) = SecureMessage.generateIdentity()
        let (bSK, bPK) = SecureMessage.generateIdentity()
        let xFile = try SecureFile.seal(Data("x".utf8), toPublicKey: bPK, senderPrivateKey: aSK)
        // abrir arquivo modo 2 como SENHA é REJEITADO (curto/versão) — nunca decifra.
        XCTAssertThrowsError(try SecureFile.open(xFile, password: "pw"))
        // abrir arquivo de SENHA como modo 2 também é rejeitado.
        let pwFile = try SecureFile.seal(Data("x".utf8), password: "pw", params: .testFast())
        XCTAssertThrowsError(try SecureFile.open(pwFile, recipientPrivateKey: bSK, senderCandidates: [aPK]))
    }

    /// Integração com o envelope de nome/tipo: um arquivo enviado a um contato preserva nome e tipo.
    func testX25519_withFileEnvelope() throws {
        let (aSK, aPK) = SecureMessage.generateIdentity()
        let (bSK, bPK) = SecureMessage.generateIdentity()
        let wrapped = FileEnvelope.wrap(Data("áudio".utf8), name: "recado.m4a", uti: "public.mpeg-4-audio")
        let sealed = try SecureFile.seal(wrapped, toPublicKey: bPK, senderPrivateKey: aSK)
        let (opened, _) = try SecureFile.open(sealed, recipientPrivateKey: bSK, senderCandidates: [aPK])
        let d = FileEnvelope.unwrap(opened)
        XCTAssertEqual(d.name, "recado.m4a")
        XCTAssertEqual(d.data, Data("áudio".utf8))
    }
}
