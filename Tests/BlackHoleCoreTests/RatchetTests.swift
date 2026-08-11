import XCTest
@testable import BlackHoleCore

/// Double Ratchet (mensagens com forward secrecy, sem servidor). Round-trip, fora de ordem, perda,
/// replay, adulteração, estado que não dessincroniza com bloco forjado, persistência (Codable),
/// teto anti-DoS e roteamento. `@testable` para inspecionar o estado interno.
final class RatchetTests: XCTestCase {

    /// Cria uma sessão dos dois lados e devolve (iniciador, responder) já nos papéis certos.
    private func makePair() -> (initiator: RatchetState, responder: RatchetState) {
        let (aSK, aPK) = SecureMessage.generateIdentity()
        let (bSK, bPK) = SecureMessage.generateIdentity()
        let a = try! DoubleRatchet.initialize(identityPrivateKey: aSK, identityPublicKey: aPK, peerIdentityPublicKey: bPK)
        let b = try! DoubleRatchet.initialize(identityPrivateKey: bSK, identityPublicKey: bPK, peerIdentityPublicKey: aPK)
        return a.sendCK != nil ? (a, b) : (b, a)   // o iniciador já nasce com cadeia de envio
    }

    private func enc(_ s: String, _ st: inout RatchetState) throws -> String {
        try DoubleRatchet.encrypt(Data(s.utf8), state: &st)
    }
    private func dec(_ block: String, _ st: inout RatchetState) throws -> String {
        String(decoding: try DoubleRatchet.decrypt(block, state: &st), as: UTF8.self)
    }

    // MARK: - Round-trip

    func testBasicRoundTrip() throws {
        var (i, r) = makePair()
        XCTAssertEqual(try dec(try enc("oi", &i), &r), "oi")
        XCTAssertEqual(try dec(try enc("olá de volta", &r), &i), "olá de volta")
    }

    func testBackAndForth_ratchets() throws {
        var (i, r) = makePair()
        for k in 0..<6 {
            XCTAssertEqual(try dec(try enc("i\(k)", &i), &r), "i\(k)")
            XCTAssertEqual(try dec(try enc("r\(k)", &r), &i), "r\(k)")
        }
    }

    func testMultipleInARow() throws {
        var (i, r) = makePair()
        let blocks = try (0..<5).map { try enc("m\($0)", &i) }
        for k in 0..<5 { XCTAssertEqual(try dec(blocks[k], &r), "m\(k)") }
    }

    // MARK: - Papéis

    func testResponderCannotSendFirst() throws {
        var (_, r) = makePair()
        XCTAssertThrowsError(try DoubleRatchet.encrypt(Data("x".utf8), state: &r)) {
            XCTAssertEqual($0 as? RatchetError, .notReady)
        }
    }

    func testResponderCanReplyAfterFirstReceive() throws {
        var (i, r) = makePair()
        _ = try dec(try enc("oi", &i), &r)
        XCTAssertEqual(try dec(try enc("agora posso", &r), &i), "agora posso")
    }

    // MARK: - Fora de ordem / perda

    func testOutOfOrder() throws {
        var (i, r) = makePair()
        let b0 = try enc("m0", &i), b1 = try enc("m1", &i), b2 = try enc("m2", &i)
        XCTAssertEqual(try dec(b2, &r), "m2")   // chega primeiro
        XCTAssertEqual(try dec(b0, &r), "m0")   // via chave pulada
        XCTAssertEqual(try dec(b1, &r), "m1")
    }

    func testLostMessage_laterOnesStillOpen() throws {
        var (i, r) = makePair()
        let b0 = try enc("m0", &i), b1 = try enc("m1", &i), b2 = try enc("m2", &i)
        XCTAssertEqual(try dec(b0, &r), "m0")
        XCTAssertEqual(try dec(b2, &r), "m2")   // m1 "perdida"
        XCTAssertEqual(try dec(b1, &r), "m1")   // chega atrasada, ainda abre
    }

    func testOutOfOrder_acrossRatchet() throws {
        var (i, r) = makePair()
        // i manda 2, r recebe e responde (ratchet), i responde de novo — mistura as cadeias.
        let a0 = try enc("a0", &i), a1 = try enc("a1", &i)
        XCTAssertEqual(try dec(a0, &r), "a0")
        let rb = try enc("rb", &r)
        XCTAssertEqual(try dec(rb, &i), "rb")
        let a2 = try enc("a2", &i)              // nova cadeia de i
        // r recebe a2 (cadeia nova) ANTES de a1 (cadeia velha)
        XCTAssertEqual(try dec(a2, &r), "a2")
        XCTAssertEqual(try dec(a1, &r), "a1")   // pulada da cadeia velha
    }

    // MARK: - Replay / forward secrecy

    func testReplay_fails_keyConsumed() throws {
        var (i, r) = makePair()
        let b0 = try enc("uma vez", &i)
        XCTAssertEqual(try dec(b0, &r), "uma vez")
        XCTAssertThrowsError(try DoubleRatchet.decrypt(b0, state: &r)) {
            XCTAssertEqual($0 as? RatchetError, .undecryptable)   // chave já descartada
        }
    }

    func testForwardSecrecy_ratchetKeyChanges() throws {
        var (i, r) = makePair()
        let pub0 = i.dhSelfPub
        _ = try dec(try enc("1", &i), &r)
        _ = try dec(try enc("2", &r), &i)       // i faz DH-ratchet ao receber
        XCTAssertNotEqual(i.dhSelfPub, pub0)    // chave de ratchet girou
    }

    // MARK: - Adulteração / robustez de estado

    func testTamper_fails() throws {
        var (i, r) = makePair()
        var block = try enc("segredo", &i)
        block.removeLast(2); block.append("ZZ")   // corrompe o ciphertext/tag
        XCTAssertThrowsError(try DoubleRatchet.decrypt(block, state: &r))
    }

    func testForgedBlock_doesNotDesyncState() throws {
        var (i, r) = makePair()
        let good = try enc("válida", &i)          // n=0
        var bad = good; bad.removeLast(2); bad.append("ZZ")
        XCTAssertThrowsError(try DoubleRatchet.decrypt(bad, state: &r))   // falha
        XCTAssertEqual(try dec(good, &r), "válida")                       // estado intacto, abre
    }

    // MARK: - Persistência (Codable)

    func testStateCodableRoundTrip() throws {
        var (i, r) = makePair()
        _ = try dec(try enc("antes", &i), &r)
        var i2 = try JSONDecoder().decode(RatchetState.self, from: JSONEncoder().encode(i))
        var r2 = try JSONDecoder().decode(RatchetState.self, from: JSONEncoder().encode(r))
        // conversa continua com os estados restaurados
        XCTAssertEqual(try dec(try enc("depois", &r2), &i2), "depois")
        XCTAssertEqual(try dec(try enc("e mais", &i2), &r2), "e mais")
    }

    // MARK: - Anti-DoS (teto de skip)

    func testSkipLimitExceeded() throws {
        var (i, r) = makePair()
        var last = ""
        for k in 0...101 { last = try enc("m\(k)", &i) }   // 102 mensagens (n=0..101)
        XCTAssertThrowsError(try DoubleRatchet.decrypt(last, state: &r)) {
            XCTAssertEqual($0 as? RatchetError, .skipLimitExceeded)   // gap 101 > 100
        }
    }

    func testSkipAtLimit_ok() throws {
        var (i, r) = makePair()
        var last = ""
        for k in 0...100 { last = try enc("m\(k)", &i) }   // 101 mensagens (n=0..100), gap 100 = teto
        XCTAssertEqual(try dec(last, &r), "m100")
    }

    // MARK: - Formato / roteamento

    func testWireFormat_andRouting() throws {
        var (i, _) = makePair()
        let block = try enc("x", &i)
        XCTAssertTrue(block.hasPrefix("BLKH01E."))
        XCTAssertTrue(DoubleRatchet.isRatchetMessage(block))
        XCTAssertNil(SecureMessage.mode(of: block))   // não é bloco de SecureMessage

        let sm = try SecureMessage.encrypt(Data("y".utf8), password: "pw", params: .testFast())
        XCTAssertFalse(DoubleRatchet.isRatchetMessage(sm))   // e vice-versa
    }

    func testInitialize_rejectsBadInput() {
        let (sk, pk) = SecureMessage.generateIdentity()
        XCTAssertThrowsError(try DoubleRatchet.initialize(identityPrivateKey: sk, identityPublicKey: pk,
                                                          peerIdentityPublicKey: pk)) {   // par == eu
            XCTAssertEqual($0 as? RatchetError, .malformed)
        }
        XCTAssertThrowsError(try DoubleRatchet.initialize(identityPrivateKey: Data([1,2,3]),
                                                          identityPublicKey: pk, peerIdentityPublicKey: pk))
    }
}
