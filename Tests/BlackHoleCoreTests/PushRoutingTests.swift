import XCTest
import CryptoKit
@testable import BlackHoleCore

/// A propriedade que sustenta o desenho inteiro: o que EU registro (`mine`) tem de ser BIT A BIT
/// igual ao que meu CONTATO calcula sozinho quando quer me acordar (`forPeer`) — sem handshake,
/// sem transmitir nada. Se essa igualdade falhar, o push relay nunca acha ninguém.
final class PushRoutingTests: XCTestCase {
    private func keypair() -> (sk: Data, pk: Data) {
        let sk = Curve25519.KeyAgreement.PrivateKey()
        return (sk.rawRepresentation, sk.publicKey.rawRepresentation)
    }

    func testMineEqualsWhatThePeerComputes_bothDirections() throws {
        let alice = keypair(), bob = keypair()

        let aliceMine = try XCTUnwrap(PushRouting.mine(myPrivateKey: alice.sk, myPublicKey: alice.pk, peerPublicKey: bob.pk))
        let bobSeesAlice = try XCTUnwrap(PushRouting.forPeer(myPrivateKey: bob.sk, myPublicKey: bob.pk, peerPublicKey: alice.pk))
        XCTAssertEqual(aliceMine.routingID, bobSeesAlice.routingID)
        XCTAssertEqual(aliceMine.proof, bobSeesAlice.proof)

        let bobMine = try XCTUnwrap(PushRouting.mine(myPrivateKey: bob.sk, myPublicKey: bob.pk, peerPublicKey: alice.pk))
        let aliceSeesBob = try XCTUnwrap(PushRouting.forPeer(myPrivateKey: alice.sk, myPublicKey: alice.pk, peerPublicKey: bob.pk))
        XCTAssertEqual(bobMine.routingID, aliceSeesBob.routingID)
        XCTAssertEqual(bobMine.proof, aliceSeesBob.proof)
    }

    /// As duas direções do MESMO par têm de ser DIFERENTES — senão acordar Alice acordaria Bob
    /// também (o par compartilhando uma única entrada no relay).
    func testTheTwoDirectionsOfAPairDiffer() throws {
        let alice = keypair(), bob = keypair()
        let aliceMine = try XCTUnwrap(PushRouting.mine(myPrivateKey: alice.sk, myPublicKey: alice.pk, peerPublicKey: bob.pk))
        let bobMine = try XCTUnwrap(PushRouting.mine(myPrivateKey: bob.sk, myPublicKey: bob.pk, peerPublicKey: alice.pk))
        XCTAssertNotEqual(aliceMine.routingID, bobMine.routingID)
        XCTAssertNotEqual(aliceMine.proof, bobMine.proof)
    }

    /// routingID e proof não podem ser o mesmo valor (tags de derivação diferentes) — senão
    /// registrar no relay já revelaria o proof.
    func testRoutingIDAndProofDiffer() throws {
        let alice = keypair(), bob = keypair()
        let c = try XCTUnwrap(PushRouting.mine(myPrivateKey: alice.sk, myPublicKey: alice.pk, peerPublicKey: bob.pk))
        XCTAssertNotEqual(c.routingID, c.proof)
    }

    /// Pares diferentes não podem colidir: o mesmo Bob, visto por dois contatos diferentes, tem
    /// credenciais diferentes (é o que dá "menos correlação para os remetentes" do desenho).
    func testDifferentPairsGiveDifferentCredentials() throws {
        let bob = keypair(), alice = keypair(), carol = keypair()
        let bobForAlice = try XCTUnwrap(PushRouting.mine(myPrivateKey: bob.sk, myPublicKey: bob.pk, peerPublicKey: alice.pk))
        let bobForCarol = try XCTUnwrap(PushRouting.mine(myPrivateKey: bob.sk, myPublicKey: bob.pk, peerPublicKey: carol.pk))
        XCTAssertNotEqual(bobForAlice.routingID, bobForCarol.routingID)
    }

    func testInvalidKeys_returnNil() {
        let short = Data(repeating: 1, count: 10)
        let valid = keypair().pk
        XCTAssertNil(PushRouting.mine(myPrivateKey: short, myPublicKey: valid, peerPublicKey: valid))
        XCTAssertNil(PushRouting.mine(myPrivateKey: keypair().sk, myPublicKey: valid, peerPublicKey: valid))  // pares == → direção indefinida
    }

    func testDeterministic_sameInputsSameOutput() throws {
        let alice = keypair(), bob = keypair()
        let a = try XCTUnwrap(PushRouting.mine(myPrivateKey: alice.sk, myPublicKey: alice.pk, peerPublicKey: bob.pk))
        let b = try XCTUnwrap(PushRouting.mine(myPrivateKey: alice.sk, myPublicKey: alice.pk, peerPublicKey: bob.pk))
        XCTAssertEqual(a, b)
    }
}
