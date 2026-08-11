import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Fuzzing DETERMINÍSTICO dos parsers que recebem dados de canal hostil (bloco colado/recebido).
/// Complementa os AdversarialTests (casos pensados) com varredura exaustiva e mutação aleatória
/// de semente FIXA (reproduzível: uma falha aqui refaz sempre igual, sem flakiness).
///
/// Invariantes verificadas — para QUALQUER entrada:
///  1. nunca crashar (nem trap, nem loop);
///  2. nunca devolver plaintext DIFERENTE do original (fail-closed: ou abre exato, ou lança);
///  3. um bloco adulterado nunca dessincroniza o estado do ratchet.
final class FuzzTests: XCTestCase {

    /// PRNG SplitMix64 com semente fixa — mutações reproduzíveis (nada de SystemRandom aqui).
    private struct SplitMix64 {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
        mutating func below(_ n: Int) -> Int { Int(next() % UInt64(n)) }
    }

    private func b64u(_ d: Data) -> String {
        d.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    private func armor(_ payload: Data) -> String { "BLKH01E.1.\(b64u(payload))" }
    private func payload(of armored: String) -> Data {
        let b64 = String(armored.split(separator: ".")[2])
        var s = b64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)!
    }

    // Chaves fixas (as mesmas fixtures do interop) — o fuzz é 100% determinístico.
    private let senderSK = Data((1...32).map { UInt8($0) })
    private let recipSK = Data((0xA0...0xBF).map { UInt8($0) })

    private func makeX25519Block(_ text: String = "alvo do fuzz 🎯") throws -> (block: String, recipSK: Data, senderPK: Data, plain: Data) {
        let senderPK = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: senderSK).publicKey.rawRepresentation
        let recipPK = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipSK).publicKey.rawRepresentation
        let plain = Data(text.utf8)
        let block = try SecureMessage.encrypt(plain, toPublicKey: recipPK, senderPrivateKey: senderSK)
        return (block, recipSK, senderPK, plain)
    }

    // MARK: - Byte-flip exaustivo (modo 2, X25519 — rápido, dá para varrer TODA posição)

    /// Inverte (XOR 0xFF) cada byte do payload, um por vez: TODAS as posições têm que falhar
    /// fechado — header (AAD autentica), nonce, ciphertext e tag. Nenhuma pode crashar nem abrir.
    func testByteFlip_x25519Block_everyPositionFailsClosed() throws {
        let f = try makeX25519Block()
        let base = payload(of: f.block)
        for i in 0..<base.count {
            var mutated = base
            mutated[i] ^= 0xFF
            XCTAssertThrowsError(
                try SecureMessage.decrypt(armor(mutated), recipientPrivateKey: f.recipSK,
                                          senderCandidates: [f.senderPK]),
                "flip do byte \(i) NÃO pode abrir")
        }
    }

    /// Truncagem em TODO comprimento possível do payload: nunca crashar, nunca abrir.
    func testTruncation_everyLength_failsClosed() throws {
        let f = try makeX25519Block()
        let base = payload(of: f.block)
        for len in 0..<base.count {
            XCTAssertThrowsError(
                try SecureMessage.decrypt(armor(base.prefix(len)), recipientPrivateKey: f.recipSK,
                                          senderCandidates: [f.senderPK]))
        }
    }

    // MARK: - Byte-flip do ratchet (+ estado nunca dessincroniza)

    func testByteFlip_ratchetBlock_everyPositionFailsClosed_stateIntact() throws {
        let (aSK, aPK) = SecureMessage.generateIdentity()
        let (bSK, bPK) = SecureMessage.generateIdentity()
        var a = try DoubleRatchet.initialize(identityPrivateKey: aSK, identityPublicKey: aPK, peerIdentityPublicKey: bPK)
        var b = try DoubleRatchet.initialize(identityPrivateKey: bSK, identityPublicKey: bPK, peerIdentityPublicKey: aPK)
        if a.sendCK == nil { swap(&a, &b) }   // a = iniciador

        let good = try DoubleRatchet.encrypt(Data("mensagem íntegra".utf8), state: &a)
        let base = payload(of: good)
        for i in 0..<base.count {
            var mutated = base
            mutated[i] ^= 0xFF
            var probe = b   // cada tentativa parte do MESMO estado
            XCTAssertThrowsError(try DoubleRatchet.decrypt(armor(mutated), state: &probe),
                                 "flip do byte \(i) NÃO pode abrir")
        }
        // Depois de ~300 blocos forjados, o estado REAL segue intacto e abre o bloco bom.
        XCTAssertEqual(try DoubleRatchet.decrypt(good, state: &b), Data("mensagem íntegra".utf8))
    }

    // MARK: - Modo senha (Argon2id é caro → flip só no header + amostra do selado)

    /// Usa o vetor congelado (params rápidos de teste). Flip de cada byte do HEADER (30) — magic,
    /// versão, modo, ops/mem (anti-DoS tem que barrar ANTES de alocar Argon2id gigante) e salt —
    /// mais uma amostra do trecho selado. Tudo falha fechado com a senha CERTA.
    func testByteFlip_passwordBlockHeader_failsClosed() throws {
        let frozen = "BLKH01E.1.QkgwMQEBAAAAAgQAAABy4XdN9qZu_ta-osFRM_U38HIhdsCi_v4BhkX_9-hQ-K-84h6NypYDUHcKRpoPEOtUeCVYmKsksuyBXdDklFg0b_iUSYwxFgUEymXeA28-3KVN3Y9bjTStDUiB63XynTxil-mOta27kE95G_u59fqkXCsN4LiUos7nec20KpdPRzsH1HdetkAoES3TTj3PgtQ1SzI0wuK8aHpwn0mg8WeFN-XMk3oEAvVfkKRdJwDTCUv1ZxGo26fsKh1PV-0KFtuF8gDXLk_zBHbKrZ4fmd_Frw-5W-LTkxhEBXfMiJ6uQwc_Lxx8R4YV2tpgMgNN_eRGaO-vhj-Dl8wnCgf-Pw7gs0oymlFy02_e0S5NSF7TdVHfGv5uIdRfOT3ItesU7o0MsuFLIZyobuvcpuQ"
        let base = payload(of: frozen)
        var positions = Array(0..<30)                       // header inteiro
        positions += [30, 41, base.count / 2, base.count - 1]   // nonce, início do ct, meio, tag
        for i in positions {
            var mutated = base
            mutated[i] ^= 0xFF
            XCTAssertThrowsError(try SecureMessage.decrypt(armor(mutated), password: "senha-fixa-v1"),
                                 "flip do byte \(i) NÃO pode abrir")
        }
    }

    // MARK: - Lixo aleatório (semente fixa) nos pontos de entrada

    /// 2 000 entradas mutadas/aleatórias contra todos os parsers de borda: extractToken, mode,
    /// decrypt (2 modos), isRatchetMessage, DoubleRatchet.decrypt. Vale a invariante 2: se abrir
    /// (mutação neutra de base64 — bits descartados do último quantum), o plaintext é o ORIGINAL.
    func testRandomMutations_neverCrash_neverWrongPlaintext() throws {
        let f = try makeX25519Block()
        var rng = SplitMix64(state: 0xB1AC4801E)
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!@# çãé🕳")

        for round in 0..<2_000 {
            var input: String
            switch round % 4 {
            case 0:   // bloco válido com 1–8 chars trocados
                var chars = Array(f.block)
                for _ in 0...(rng.below(8)) { chars[rng.below(chars.count)] = alphabet[rng.below(alphabet.count)] }
                input = String(chars)
            case 1:   // lixo curto aleatório
                input = String((0..<rng.below(64)).map { _ in alphabet[rng.below(alphabet.count)] })
            case 2:   // prefixo quase-válido + cauda aleatória
                input = "BLKH01E.\(rng.below(10))." +
                    String((0..<rng.below(300)).map { _ in alphabet[rng.below(alphabet.count)] })
            default:  // bloco válido truncado no meio de um caractere qualquer
                input = String(f.block.prefix(rng.below(f.block.count)))
            }

            _ = SecureMessage.isMessage(input)
            _ = SecureMessage.mode(of: input)
            _ = DoubleRatchet.isRatchetMessage(input)
            if let pt = try? SecureMessage.decrypt(input, recipientPrivateKey: f.recipSK,
                                                   senderCandidates: [f.senderPK]) {
                XCTAssertEqual(pt.plaintext, f.plain, "round \(round): abriu com plaintext ERRADO")
            }
            var dummy = try DoubleRatchet.initialize(identityPrivateKey: recipSK,
                                                     identityPublicKey: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipSK).publicKey.rawRepresentation,
                                                     peerIdentityPublicKey: f.senderPK)
            _ = try? DoubleRatchet.decrypt(input, state: &dummy)
        }
    }

    /// Entradas patológicas de tamanho: regex/tetos não podem travar nem estourar.
    func testPathologicalSizes_boundedAndFast() {
        let huge = "BLKH01E.1." + String(repeating: "A", count: 3_000_000)   // > teto de 2 MB
        XCTAssertNil(SecureMessage.extractToken(from: huge))
        XCTAssertFalse(DoubleRatchet.isRatchetMessage(huge))
        let manyDots = String(repeating: "BLKH01E.", count: 50_000)
        XCTAssertNil(SecureMessage.extractToken(from: manyDots))
    }

    // MARK: - Confusão de modo/roteamento (bloco certo no decodificador errado)

    func testModeConfusion_wrongDecoder_failsClosed() throws {
        let f = try makeX25519Block()
        // Bloco X25519 no caminho de senha → unsupportedVersion (nunca pede Argon2id).
        XCTAssertThrowsError(try SecureMessage.decrypt(f.block, password: "qualquer")) {
            XCTAssertEqual($0 as? MessageError, .unsupportedVersion)
        }
        // Bloco de ratchet no SecureMessage → malformed (magic BHR1 ≠ BH01) — e vice-versa.
        let (aSK, aPK) = SecureMessage.generateIdentity()
        let (bSK, bPK) = SecureMessage.generateIdentity()
        var a = try DoubleRatchet.initialize(identityPrivateKey: aSK, identityPublicKey: aPK, peerIdentityPublicKey: bPK)
        var b = try DoubleRatchet.initialize(identityPrivateKey: bSK, identityPublicKey: bPK, peerIdentityPublicKey: aPK)
        if a.sendCK == nil { swap(&a, &b) }
        let ratchetBlock = try DoubleRatchet.encrypt(Data("x".utf8), state: &a)

        XCTAssertThrowsError(try SecureMessage.decrypt(ratchetBlock, password: "x")) {
            XCTAssertEqual($0 as? MessageError, .malformed)
        }
        XCTAssertThrowsError(try SecureMessage.decrypt(ratchetBlock, recipientPrivateKey: f.recipSK,
                                                       senderCandidates: [f.senderPK])) {
            XCTAssertEqual($0 as? MessageError, .malformed)
        }
        var probe = b
        XCTAssertThrowsError(try DoubleRatchet.decrypt(f.block, state: &probe)) {
            XCTAssertEqual($0 as? RatchetError, .malformed)
        }
        // O roteador distingue os dois formatos.
        XCTAssertTrue(DoubleRatchet.isRatchetMessage(ratchetBlock))
        XCTAssertFalse(DoubleRatchet.isRatchetMessage(f.block))
        XCTAssertEqual(SecureMessage.mode(of: f.block), 2)
    }
}
