import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Modo X25519 (mode 2) do SecureMessage: cifra para a chave pública do destinatário, autentica o
/// remetente pelo ECDH, sem senha e sem revelar a pública do remetente no bloco.
final class SecureMessageX25519Tests: XCTestCase {

    private func id() -> (privateKey: Data, publicKey: Data) { SecureMessage.generateIdentity() }

    func testRoundTrip_recipientDecrypts_andRecoversSender() throws {
        let alice = id(), bob = id()
        let msg = Data("encontro às 20h, sem telefone".utf8)
        let armored = try SecureMessage.encrypt(msg, toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        let (plain, sender) = try SecureMessage.decrypt(armored, recipientPrivateKey: bob.privateKey,
                                                        senderCandidates: [alice.publicKey])
        XCTAssertEqual(plain, msg)
        XCTAssertEqual(sender, alice.publicKey, "o remetente autenticado é a Alice")
    }

    func testDecrypt_picksRightSender_amongCandidates() throws {
        let alice = id(), bob = id(), carol = id(), dave = id()
        let armored = try SecureMessage.encrypt(Data("oi".utf8), toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        // Bob tem vários contatos; só a chave da Alice abre.
        let (_, sender) = try SecureMessage.decrypt(armored, recipientPrivateKey: bob.privateKey,
                                                    senderCandidates: [carol.publicKey, dave.publicKey, alice.publicKey])
        XCTAssertEqual(sender, alice.publicKey)
    }

    func testWrongRecipient_fails() throws {
        let alice = id(), bob = id(), carol = id()
        let armored = try SecureMessage.encrypt(Data("segredo".utf8), toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        // Carol (não é a destinatária) não abre, mesmo tendo a Alice como candidata.
        XCTAssertThrowsError(try SecureMessage.decrypt(armored, recipientPrivateKey: carol.privateKey,
                                                       senderCandidates: [alice.publicKey])) {
            XCTAssertEqual($0 as? MessageError, .wrongPasswordOrCorrupt)
        }
    }

    func testSenderNotInCandidates_fails() throws {
        let alice = id(), bob = id(), carol = id()
        let armored = try SecureMessage.encrypt(Data("x".utf8), toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        // Bob é o destinatário certo, mas não tem a Alice como contato → não descobre a chave.
        XCTAssertThrowsError(try SecureMessage.decrypt(armored, recipientPrivateKey: bob.privateKey,
                                                       senderCandidates: [carol.publicKey])) {
            XCTAssertEqual($0 as? MessageError, .wrongPasswordOrCorrupt)
        }
    }

    func testTamper_fails() throws {
        let alice = id(), bob = id()
        var armored = try SecureMessage.encrypt(Data("integridade".utf8), toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        // Adultera um caractere no meio do payload base64url.
        let idx = armored.index(armored.startIndex, offsetBy: armored.count - 6)
        let c = armored[idx]
        let repl: Character = c == "A" ? "B" : "A"
        armored.replaceSubrange(idx...idx, with: String(repl))
        XCTAssertThrowsError(try SecureMessage.decrypt(armored, recipientPrivateKey: bob.privateKey,
                                                       senderCandidates: [alice.publicKey]))
    }

    func testEmptyMessage_roundTrips() throws {
        let alice = id(), bob = id()
        let armored = try SecureMessage.encrypt(Data(), toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        let (plain, _) = try SecureMessage.decrypt(armored, recipientPrivateKey: bob.privateKey,
                                                   senderCandidates: [alice.publicKey])
        XCTAssertEqual(plain, Data())
    }

    // MARK: - Roteamento por modo (não confundir com o modo senha v1)

    func testMode_detection() throws {
        let alice = id(), bob = id()
        let x = try SecureMessage.encrypt(Data("a".utf8), toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        XCTAssertEqual(SecureMessage.mode(of: x), 2)
        let pw = try SecureMessage.encrypt(Data("a".utf8), password: "12345678", params: .testFast())
        XCTAssertEqual(SecureMessage.mode(of: pw), 1)
        XCTAssertNil(SecureMessage.mode(of: "não é um bloco"))
    }

    func testCrossMode_rejected() throws {
        let alice = id(), bob = id()
        let x = try SecureMessage.encrypt(Data("a".utf8), toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        // Bloco X25519 aberto pela via SENHA → versão/modo não suportado.
        XCTAssertThrowsError(try SecureMessage.decrypt(x, password: "12345678")) {
            XCTAssertEqual($0 as? MessageError, .unsupportedVersion)
        }
        // Bloco SENHA aberto pela via X25519 → idem.
        let pw = try SecureMessage.encrypt(Data("a".utf8), password: "12345678", params: .testFast())
        XCTAssertThrowsError(try SecureMessage.decrypt(pw, recipientPrivateKey: bob.privateKey,
                                                       senderCandidates: [alice.publicKey])) {
            XCTAssertEqual($0 as? MessageError, .unsupportedVersion)
        }
    }

    func testPaddingHidesLength() throws {
        // Duas mensagens de tamanhos diferentes (mas no mesmo bloco de padding) → payloads de mesmo tamanho.
        let alice = id(), bob = id()
        let a = try SecureMessage.encrypt(Data(repeating: 65, count: 10), toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        let b = try SecureMessage.encrypt(Data(repeating: 66, count: 50), toPublicKey: bob.publicKey, senderPrivateKey: alice.privateKey)
        XCTAssertEqual(a.count, b.count, "padding de 256 arredonda 10 e 50 para o mesmo tamanho")
    }
}
