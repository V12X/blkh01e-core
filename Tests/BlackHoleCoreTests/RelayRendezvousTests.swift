import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Rendezvous da sessão ao vivo: os dois lados derivam a MESMA caixa sem handshake, com rotação
/// diária e split por direção (sem eco das próprias mensagens). Núcleo headless — zero rede.
final class RelayRendezvousTests: XCTestCase {

    /// Par de identidade determinístico a partir de um byte-semente (32 B iguais). X25519 aceita
    /// qualquer 32 B (clampa internamente), então serve para vetores reproduzíveis.
    private func identity(_ seed: UInt8) -> (priv: Data, pub: Data) {
        let sk = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: seed, count: 32))
        return (sk.rawRepresentation, sk.publicKey.rawRepresentation)
    }

    private let epoch = 1_760_000_000.0   // um instante fixo qualquer (2025) para os vetores

    // MARK: - Invariante central: os dois lados se encontram

    func testAgreement_aliceReachesBob_andViceVersa() {
        let a = identity(0x0A), b = identity(0x0B)
        guard let alice = RelayRendezvous.endpoints(myPrivateKey: a.priv, myPublicKey: a.pub,
                                                    peerPublicKey: b.pub, epoch: epoch),
              let bob = RelayRendezvous.endpoints(myPrivateKey: b.priv, myPublicKey: b.pub,
                                                  peerPublicKey: a.pub, epoch: epoch) else {
            return XCTFail("endpoints devolveu nil")
        }
        // O que Alice PUBLICA hoje, Bob ASSINA (está na janela dele) — e o simétrico.
        XCTAssertTrue(bob.subscribe.contains(alice.publish), "Bob não assina a caixa de Alice")
        XCTAssertTrue(alice.subscribe.contains(bob.publish), "Alice não assina a caixa de Bob")
    }

    // MARK: - Split de direção: sem eco das próprias mensagens

    func testDirectionSplit_noSelfEcho() {
        let a = identity(0x0A), b = identity(0x0B)
        let alice = RelayRendezvous.endpoints(myPrivateKey: a.priv, myPublicKey: a.pub,
                                              peerPublicKey: b.pub, epoch: epoch)!
        let bob = RelayRendezvous.endpoints(myPrivateKey: b.priv, myPublicKey: b.pub,
                                            peerPublicKey: a.pub, epoch: epoch)!
        // Cada um publica numa caixa que ele MESMO não assina.
        XCTAssertFalse(alice.subscribe.contains(alice.publish), "Alice receberia o próprio eco")
        XCTAssertFalse(bob.subscribe.contains(bob.publish), "Bob receberia o próprio eco")
        // As caixas de publicação dos dois são diferentes (direções opostas).
        XCTAssertNotEqual(alice.publish, bob.publish)
    }

    func testSendDirection_isOpposite() {
        let a = identity(0x0A), b = identity(0x0B)
        let dirA = RelayRendezvous.sendDirection(myPublicKey: a.pub, peerPublicKey: b.pub)
        let dirB = RelayRendezvous.sendDirection(myPublicKey: b.pub, peerPublicKey: a.pub)
        XCTAssertNotNil(dirA); XCTAssertNotNil(dirB)
        XCTAssertNotEqual(dirA, dirB)   // exatamente um é "hi"
    }

    // MARK: - Determinismo e rotação

    func testDeterministic() {
        let a = identity(0x0A), b = identity(0x0B)
        let e1 = RelayRendezvous.endpoints(myPrivateKey: a.priv, myPublicKey: a.pub, peerPublicKey: b.pub, epoch: epoch)
        let e2 = RelayRendezvous.endpoints(myPrivateKey: a.priv, myPublicKey: a.pub, peerPublicKey: b.pub, epoch: epoch)
        XCTAssertEqual(e1, e2)
    }

    func testDayRotation_mailboxChangesPerDay() {
        let a = identity(0x0A), b = identity(0x0B)
        let secret = RelayRendezvous.pairSecret(myPrivateKey: a.priv, peerPublicKey: b.pub)!
        let m1 = RelayRendezvous.mailboxHex(pairSecret: secret, day: 100, direction: 0)
        let m2 = RelayRendezvous.mailboxHex(pairSecret: secret, day: 101, direction: 0)
        XCTAssertNotEqual(m1, m2)
        // Direção também separa.
        let m3 = RelayRendezvous.mailboxHex(pairSecret: secret, day: 100, direction: 1)
        XCTAssertNotEqual(m1, m3)
    }

    func testSubscribeWindow_isYesterdayTodayTomorrow() {
        let a = identity(0x0A), b = identity(0x0B)
        let alice = RelayRendezvous.endpoints(myPrivateKey: a.priv, myPublicKey: a.pub, peerPublicKey: b.pub, epoch: epoch)!
        let secret = RelayRendezvous.pairSecret(myPrivateKey: a.priv, peerPublicKey: b.pub)!
        let recvDir = 1 - RelayRendezvous.sendDirection(myPublicKey: a.pub, peerPublicKey: b.pub)!
        let today = RelayRendezvous.dayBucket(epoch: epoch)
        let expected = [today - 1, today, today + 1].map {
            RelayRendezvous.mailboxHex(pairSecret: secret, day: $0, direction: recvDir)
        }
        XCTAssertEqual(alice.subscribe, expected)
        XCTAssertEqual(alice.subscribe.count, 3)
    }

    func testDayBucket() {
        XCTAssertEqual(RelayRendezvous.dayBucket(epoch: 0), 0)
        XCTAssertEqual(RelayRendezvous.dayBucket(epoch: 86_399), 0)
        XCTAssertEqual(RelayRendezvous.dayBucket(epoch: 86_400), 1)
        XCTAssertEqual(RelayRendezvous.dayBucket(epoch: 1_760_000_000), 1_760_000_000 / 86_400)
    }

    // MARK: - Isolamento entre pares e entradas inválidas

    func testDifferentPair_differentMailbox() {
        let a = identity(0x0A), b = identity(0x0B), c = identity(0x0C)
        let ab = RelayRendezvous.pairSecret(myPrivateKey: a.priv, peerPublicKey: b.pub)!
        let ac = RelayRendezvous.pairSecret(myPrivateKey: a.priv, peerPublicKey: c.pub)!
        XCTAssertNotEqual(ab, ac)
        XCTAssertNotEqual(RelayRendezvous.mailboxHex(pairSecret: ab, day: 100, direction: 0),
                          RelayRendezvous.mailboxHex(pairSecret: ac, day: 100, direction: 0))
    }

    func testBadInputs_returnNil() {
        let a = identity(0x0A)
        XCTAssertNil(RelayRendezvous.endpoints(myPrivateKey: Data(count: 31), myPublicKey: a.pub,
                                               peerPublicKey: a.pub, epoch: epoch))
        XCTAssertNil(RelayRendezvous.sendDirection(myPublicKey: a.pub, peerPublicKey: a.pub))  // iguais
        XCTAssertNil(RelayRendezvous.pairSecret(myPrivateKey: Data(count: 10), peerPublicKey: a.pub))
    }

    // MARK: - Vetor CONGELADO (regressão de formato)

    func testFrozenVector() {
        let a = identity(0x0A), b = identity(0x0B)
        let alice = RelayRendezvous.endpoints(myPrivateKey: a.priv, myPublicKey: a.pub,
                                              peerPublicKey: b.pub, epoch: epoch)!
        // Formato: 64 hex minúsculos.
        XCTAssertEqual(alice.publish.count, 64)
        XCTAssertTrue(alice.publish.allSatisfy { "0123456789abcdef".contains($0) })
        // Vetor CONGELADO (identidades 0x0A/0x0B, epoch 1_760_000_000). Se este valor mudar, a
        // derivação da caixa mudou — e isso quebra a interoperabilidade com clientes já publicando.
        XCTAssertEqual(alice.publish, "e6949375c29e8b4616387be3030c4cbe5fddb39e902f335beb9b25efceab145e")
    }
}
