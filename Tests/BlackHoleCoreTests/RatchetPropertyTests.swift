import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Propriedades de SEGURANÇA do Double Ratchet como comportamento observável (não só mecânica).
/// Complementa RatchetTests: sigilo entre cadeias, comprometimento de estado (cópia roubada),
/// recuperação pós-comprometimento após um round-trip completo, teto FIFO das chaves puladas e a
/// grade de fronteiras do padding (inclusive a quantização que esconde o comprimento).
final class RatchetPropertyTests: XCTestCase {

    private func makePair() -> (initiator: RatchetState, responder: RatchetState) {
        let (aSK, aPK) = SecureMessage.generateIdentity()
        let (bSK, bPK) = SecureMessage.generateIdentity()
        let a = try! DoubleRatchet.initialize(identityPrivateKey: aSK, identityPublicKey: aPK, peerIdentityPublicKey: bPK)
        let b = try! DoubleRatchet.initialize(identityPrivateKey: bSK, identityPublicKey: bPK, peerIdentityPublicKey: aPK)
        return a.sendCK != nil ? (a, b) : (b, a)
    }
    private func enc(_ s: String, _ st: inout RatchetState) throws -> String {
        try DoubleRatchet.encrypt(Data(s.utf8), state: &st)
    }
    private func dec(_ block: String, _ st: inout RatchetState) throws -> String {
        String(decoding: try DoubleRatchet.decrypt(block, state: &st), as: UTF8.self)
    }

    // MARK: - Forward secrecy operacional

    /// O estado ATUAL não reabre nada do passado — nem da cadeia corrente (replay já cobre), nem
    /// de cadeias ANTERIORES ao giro DH (este teste): sem chave pulada pendente, mensagens velhas
    /// são irrecuperáveis mesmo com o estado vivo em mãos.
    func testForwardSecrecy_previousChainBlocks_undecryptableFromCurrentState() throws {
        var (i, r) = makePair()
        let m0 = try enc("m0", &i), m1 = try enc("m1", &i)
        XCTAssertEqual(try dec(m0, &r), "m0")
        XCTAssertEqual(try dec(m1, &r), "m1")           // nada pulado: chaves consumidas
        _ = try dec(try enc("volta", &r), &i)           // giro DH no i
        XCTAssertEqual(try dec(try enc("nova cadeia", &i), &r), "nova cadeia")   // giro DH no r

        for old in [m0, m1] {
            var probe = r
            XCTAssertThrowsError(try DoubleRatchet.decrypt(old, state: &probe)) {
                XCTAssertEqual($0 as? RatchetError, .undecryptable)
            }
        }
    }

    /// Cópia ROUBADA do estado: nada do que já trafegou (e foi entregue) reabre a partir dela.
    func testStolenState_cannotReopenDeliveredHistory() throws {
        var (i, r) = makePair()
        var blocks: [String] = []
        for k in 0..<5 { blocks.append(try enc("m\(k)", &i)) }
        for (k, b) in blocks.enumerated() { XCTAssertEqual(try dec(b, &r), "m\(k)") }
        let stolen = r                                   // atacante clona o estado AGORA
        for b in blocks {
            var probe = stolen
            XCTAssertThrowsError(try DoubleRatchet.decrypt(b, state: &probe))
        }
    }

    // MARK: - Recuperação pós-comprometimento (healing)

    /// Atacante clona o estado do responder. HONESTIDADE: até o próximo giro DH ele ainda decifra
    /// o tráfego novo (janela conhecida do Double Ratchet). Depois de UM round-trip completo
    /// (r→i, i→r) — cujo frescor de chave o clone não vê — a sessão SARA: o clone perde o acesso.
    func testPostCompromise_healsAfterFullRoundTrip() throws {
        var (i, r) = makePair()
        XCTAssertEqual(try dec(try enc("pré", &i), &r), "pré")
        var stolen = r                                   // ── comprometimento aqui ──

        // Janela documentada: a próxima cadeia de i ainda deriva de material que o clone tem.
        _ = try dec(try enc("resposta de r", &r), &i)    // giro em i (nasce par novo de i)
        let windowBlock = try enc("ainda na janela", &i)
        var probeWindow = stolen
        XCTAssertEqual(try DoubleRatchet.decrypt(windowBlock, state: &probeWindow),
                       Data("ainda na janela".utf8))     // clone AINDA lê (esperado)

        // r processa de verdade (gera par de ratchet NOVO, que o clone não conhece)…
        XCTAssertEqual(try dec(windowBlock, &r), "ainda na janela")
        _ = try dec(try enc("r gira de novo", &r), &i)   // r→i com o par novo de r
        let healed = try enc("depois do healing", &i)    // i→r keyed no par novo de r

        // …e o clone (mesmo acompanhando a janela) NÃO abre o tráfego pós-round-trip.
        _ = try? DoubleRatchet.decrypt(windowBlock, state: &stolen)   // clone seguiu o fluxo
        var probeHealed = stolen
        XCTAssertThrowsError(try DoubleRatchet.decrypt(healed, state: &probeHealed)) {
            XCTAssertEqual($0 as? RatchetError, .undecryptable)
        }
        // A sessão real segue íntegra.
        XCTAssertEqual(try dec(healed, &r), "depois do healing")
    }

    // MARK: - Teto FIFO das chaves puladas (memória limitada + expiração honesta)

    /// O estoque de chaves puladas nunca passa de maxSkip (100); ao estourar, as MAIS ANTIGAS são
    /// descartadas (FIFO) e a mensagem correspondente expira de verdade (irrecuperável). Um gap
    /// ÚNICO acima de 100 nem entra (skipLimitExceeded, coberto em RatchetTests); a evicção só
    /// acontece ACUMULANDO gaps menores — é esse caminho que este teste exercita.
    func testSkippedKeys_fifoCap_oldestEvictedAndExpired() throws {
        var (i, r) = makePair()
        let first = try enc("primeira (será expulsa)", &i)      // n=0, nunca entregue
        for _ in 1...60 { _ = try enc("ruído", &i) }            // n=1…60 nunca entregues
        let mid = try enc("meio", &i)                           // n=61 → pula 0…60 (61 chaves)
        XCTAssertEqual(try dec(mid, &r), "meio")
        XCTAssertEqual(r.skipped.count, 61)
        for _ in 1...60 { _ = try enc("ruído", &i) }            // n=62…121 nunca entregues
        let last = try enc("gatilho", &i)                       // n=122 → +60 puladas = 121 > teto
        XCTAssertEqual(try dec(last, &r), "gatilho")
        XCTAssertEqual(r.skipped.count, 100, "estoque tem que encolher de volta ao teto")

        // A chave de n=0 estava entre as 21 mais antigas expulsas → o bloco expirou de verdade.
        var probe = r
        XCTAssertThrowsError(try DoubleRatchet.decrypt(first, state: &probe)) {
            XCTAssertEqual($0 as? RatchetError, .undecryptable)
        }
    }

    // MARK: - Fronteiras do padding (anti-metadado)

    /// Roundtrip exato em TODAS as fronteiras do bloco de 256 (payload = [u32 len] || claro || zeros):
    /// claro de 252 bytes fecha exatamente 1 bloco; 253 transborda para 2. Vale no ratchet e no modo 2.
    func testPaddingBoundaries_exactRoundtrip_bothFormats() throws {
        var (i, r) = makePair()
        let sk = Data((1...32).map { UInt8($0) })
        let pk = try! SecureMessage.generateIdentity()   // destinatário qualquer
        let sizes = [0, 1, 3, 4, 251, 252, 253, 255, 256, 257, 508, 509, 511, 512, 513, 1000]
        for n in sizes {
            let payload = Data((0..<n).map { UInt8($0 % 251) })
            // Ratchet (i → r), conteúdo binário arbitrário inclusive vazio.
            let rb = try DoubleRatchet.encrypt(payload, state: &i)
            XCTAssertEqual(try DoubleRatchet.decrypt(rb, state: &r), payload, "ratchet n=\(n)")
            // SecureMessage modo 2.
            let sb = try SecureMessage.encrypt(payload, toPublicKey: pk.publicKey, senderPrivateKey: sk)
            let out = try SecureMessage.decrypt(sb, recipientPrivateKey: pk.privateKey,
                                                senderCandidates: [try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk).publicKey.rawRepresentation])
            XCTAssertEqual(out.plaintext, payload, "modo 2 n=\(n)")
        }
    }

    /// Quantização: mensagens de 1 e de 200 bytes produzem blocos do MESMO tamanho (mesmo balde
    /// de 256); 253 pula para o balde seguinte. É o que o "padding esconde o comprimento" promete.
    func testPaddingQuantization_hidesLengthWithinBucket() throws {
        var (i, _) = makePair()
        let b1 = try DoubleRatchet.encrypt(Data(repeating: 1, count: 1), state: &i)
        let b200 = try DoubleRatchet.encrypt(Data(repeating: 2, count: 200), state: &i)
        let b253 = try DoubleRatchet.encrypt(Data(repeating: 3, count: 253), state: &i)
        XCTAssertEqual(b1.count, b200.count, "1 B e 200 B têm que ser indistinguíveis no tamanho")
        XCTAssertGreaterThan(b253.count, b200.count, "253 B transborda o balde de 256")
    }
}
