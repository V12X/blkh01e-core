import XCTest
@testable import BlackHoleCore

/// Testa o motor de notas cifradas compartilháveis. Usa `.testFast()` (KDF rápido) só p/ velocidade.
final class SecureMessageTests: XCTestCase {

    private func enc(_ s: String, _ pw: String) throws -> String {
        try SecureMessage.encrypt(Data(s.utf8), password: pw, params: .testFast())
    }

    // Decodifica o payload de um bloco armado (para forjar variações adversariais).
    private func payload(of armored: String) -> Data {
        let token = SecureMessage.extractToken(from: armored)!
        var s = String(token.split(separator: ".")[2])
            .replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)!
    }
    private func rearm(_ payload: Data, outer: String = "1") -> String {
        "BLKH01E.\(outer)." + payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    func testRoundTrip() throws {
        let armored = try enc("mensagem secreta 🕳️", "senha-combinada")
        XCTAssertTrue(armored.hasPrefix("BLKH01E.1."))
        let out = try SecureMessage.decrypt(armored, password: "senha-combinada")
        XCTAssertEqual(String(data: out, encoding: .utf8), "mensagem secreta 🕳️")
    }

    func testWrongPassword_fails() throws {
        let armored = try enc("x", "certa")
        XCTAssertThrowsError(try SecureMessage.decrypt(armored, password: "errada")) {
            XCTAssertEqual($0 as? MessageError, .wrongPasswordOrCorrupt)
        }
    }

    /// Adultera um byte DO PAYLOAD (dentro do ciphertext), não o último caractere base64.
    ///
    /// A versão anterior fazia `removeLast()` + `append(last == "A" ? "B" : "A")` e falhava ~6% das
    /// vezes — dois bugs somados: (1) o `last` consultado já era o penúltimo caractere original;
    /// (2) o payload aqui tem 314 bytes (314 % 3 == 2), então os 2 bits finais do último caractere
    /// base64 são PADDING: trocar 'A'→'B' decodifica idêntico e não adultera nada. Quando o token
    /// terminava em 'A' (1/16), o "bloco adulterado" era o bloco original e o decrypt — corretamente
    /// — funcionava. Era ESTE o flake da suíte, não o teste estatístico do decoy.
    func testTamper_fails() throws {
        let armored = try enc("conteudo", "pw")
        var p = payload(of: armored)
        p[p.count - 20] ^= 0xFF          // fundo do ciphertext, longe do header
        XCTAssertThrowsError(try SecureMessage.decrypt(rearm(p), password: "pw")) {
            XCTAssertEqual($0 as? MessageError, .wrongPasswordOrCorrupt)
        }
    }

    /// Adulterar o ÚLTIMO byte do payload (a tag do Poly1305) também tem de fechar.
    func testTamper_lastPayloadByte_fails() throws {
        let armored = try enc("conteudo", "pw")
        var p = payload(of: armored)
        p[p.count - 1] ^= 0x01
        XCTAssertThrowsError(try SecureMessage.decrypt(rearm(p), password: "pw")) {
            XCTAssertEqual($0 as? MessageError, .wrongPasswordOrCorrupt)
        }
    }

    func testExtractToken_fromNoisyText() throws {
        let armored = try enc("oi", "pw")
        let noisy = "Recebi isto no zap:\n\n\(armored)\n\nconsegue abrir?"
        XCTAssertTrue(SecureMessage.isMessage(noisy))
        XCTAssertEqual(SecureMessage.extractToken(from: noisy), armored)
        XCTAssertEqual(try SecureMessage.decrypt(noisy, password: "pw"), Data("oi".utf8))
    }

    func testNotAMessage() {
        XCTAssertFalse(SecureMessage.isMessage("apenas um texto normal"))
        XCTAssertNil(SecureMessage.extractToken(from: "nada aqui"))
        XCTAssertThrowsError(try SecureMessage.decrypt("lixo", password: "pw")) {
            XCTAssertEqual($0 as? MessageError, .malformed)
        }
    }

    func testEmptyPassword_rejectedOnEncrypt() {
        XCTAssertThrowsError(try SecureMessage.encrypt(Data("x".utf8), password: "")) {
            XCTAssertEqual($0 as? MessageError, .emptyPassword)
        }
    }

    // MARK: Correções da revisão

    func testUnsupportedVersion_rejected() throws {
        var p = payload(of: try enc("x", "pw"))
        p[4] = 99                                   // versão interna (autenticada) inválida
        XCTAssertThrowsError(try SecureMessage.decrypt(rearm(p, outer: "99"), password: "pw")) {
            XCTAssertEqual($0 as? MessageError, .unsupportedVersion)
        }
    }

    func testOuterVersionMismatch_rejected() throws {
        let armored = try enc("x", "pw")
        // Só troca o rótulo externo (não autenticado); a versão interna continua 1.
        let mangled = armored.replacingOccurrences(of: "BLKH01E.1.", with: "BLKH01E.2.")
        XCTAssertThrowsError(try SecureMessage.decrypt(mangled, password: "pw")) {
            XCTAssertEqual($0 as? MessageError, .malformed)
        }
    }

    func testForgedHighKDF_rejectedBeforeDeriving() throws {
        var p = payload(of: try enc("x", "pw"))
        // memLimit = 1 GiB (Sensitive): passa em withinSaneBounds, mas excede .standard() → recusa.
        p[10] = 0x40; p[11] = 0; p[12] = 0; p[13] = 0
        XCTAssertThrowsError(try SecureMessage.decrypt(rearm(p), password: "pw")) {
            XCTAssertEqual($0 as? MessageError, .malformed)
        }
    }

    func testOversizedBlock_rejected() {
        let huge = "BLKH01E.1." + String(repeating: "A", count: 1_048_576 + 100)
        XCTAssertFalse(SecureMessage.isMessage(huge), "token acima do teto não é reconhecido")
        XCTAssertThrowsError(try SecureMessage.decrypt(huge, password: "pw")) {
            XCTAssertEqual($0 as? MessageError, .malformed)
        }
    }

    func testTooShortPayload_isMalformed() throws {
        // payload com header ok mas sealed curto demais (< nonce+tag) → malformed, não wrongPassword.
        var p = payload(of: try enc("x", "pw"))
        p = p.subdata(in: 0..<(30 + 20))   // headerLen(30) + 20 (< 28)
        XCTAssertThrowsError(try SecureMessage.decrypt(rearm(p), password: "pw")) {
            XCTAssertEqual($0 as? MessageError, .malformed)
        }
    }

    // MARK: Padding anti-metadado

    func testPadding_hidesLength() throws {
        // Duas mensagens de tamanhos MUITO diferentes (mas ambas < 256) devem gerar blocos do
        // MESMO comprimento — o tamanho exato não vaza.
        let curta = try enc("a", "pw")
        let media = try enc(String(repeating: "x", count: 200), "pw")
        XCTAssertEqual(curta.count, media.count, "padding esconde o comprimento dentro do mesmo bucket")
    }

    func testPadding_differentBuckets_forLargerMessages() throws {
        // Mensagem que ultrapassa um bucket deve ficar num bloco maior (vazamento só coarse).
        let pequena = try enc("oi", "pw")                                  // ~256
        let grande = try enc(String(repeating: "y", count: 400), "pw")     // ~512
        XCTAssertGreaterThan(grande.count, pequena.count)
    }

    func testRoundTrip_variousSizes() throws {
        for n in [0, 1, 255, 256, 257, 1000] {
            let msg = Data(repeating: 65, count: n)
            let armored = try SecureMessage.encrypt(msg, password: "pw", params: .testFast())
            let out = try SecureMessage.decrypt(armored, password: "pw")
            XCTAssertEqual(out, msg, "round-trip com \(n) bytes")
        }
    }
}
