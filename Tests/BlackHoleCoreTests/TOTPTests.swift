import XCTest
@testable import BlackHoleCore

/// TOTP/HOTP contra os VETORES OFICIAIS dos RFCs (mesma cultura dos RFCVectorTests): se a
/// implementação bate com os apêndices publicados, ela abre os mesmos códigos que o Google
/// Authenticator/Authy geram. Também: Base32 (RFC 4648 §10) e o parse de `otpauth://` como
/// entrada HOSTIL (QR de terceiros).
final class TOTPTests: XCTestCase {

    // MARK: - HOTP (RFC 4226, Apêndice D)

    /// Chave ASCII "12345678901234567890", 6 dígitos, contadores 0–9 — os 10 valores do RFC.
    func testHOTP_rfc4226_appendixD() {
        let secret = Data("12345678901234567890".utf8)
        let expected = ["755224", "287082", "359152", "969429", "338314",
                        "254676", "287922", "162583", "399871", "520489"]
        for (counter, want) in expected.enumerated() {
            XCTAssertEqual(TOTP.hotp(secret: secret, counter: UInt64(counter)), want,
                           "contador \(counter)")
        }
    }

    // MARK: - TOTP (RFC 6238, Apêndice B) — 8 dígitos, T0=0, período 30

    private let sha1Key = Data("12345678901234567890".utf8)                                   // 20 B
    private let sha256Key = Data("12345678901234567890123456789012".utf8)                     // 32 B
    private let sha512Key = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8) // 64 B

    func testTOTP_rfc6238_appendixB() {
        // (epoch, SHA1, SHA256, SHA512) — a tabela completa do RFC.
        let vectors: [(UInt64, String, String, String)] = [
            (59,          "94287082", "46119246", "90693936"),
            (1111111109,  "07081804", "68084774", "25091201"),
            (1111111111,  "14050471", "67062674", "99943326"),
            (1234567890,  "89005924", "91819424", "93441116"),
            (2000000000,  "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ]
        for (t, s1, s256, s512) in vectors {
            let date = Date(timeIntervalSince1970: TimeInterval(t))
            XCTAssertEqual(TOTP.code(for: .init(secret: sha1Key, digits: 8), at: date), s1, "SHA1 @\(t)")
            XCTAssertEqual(TOTP.code(for: .init(secret: sha256Key, digits: 8, algorithm: .sha256), at: date),
                           s256, "SHA256 @\(t)")
            XCTAssertEqual(TOTP.code(for: .init(secret: sha512Key, digits: 8, algorithm: .sha512), at: date),
                           s512, "SHA512 @\(t)")
        }
    }

    /// O caso de USO real (6 dígitos, SHA1): em T dentro da 2ª janela (t=59 → contador 1), o TOTP
    /// tem que igualar o HOTP de contador 1 do RFC 4226 ("287082").
    func testTOTP_sixDigits_matchesHOTPCounter() {
        let date = Date(timeIntervalSince1970: 59)
        XCTAssertEqual(TOTP.code(for: .init(secret: sha1Key), at: date), "287082")
    }

    // MARK: - Base32 (RFC 4648 §10)

    func testBase32_rfc4648_vectors() {
        let vectors: [(String, String)] = [
            ("", ""), ("MY======", "f"), ("MZXQ====", "fo"), ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"), ("MZXW6YTB", "fooba"), ("MZXW6YTBOI======", "foobar"),
        ]
        for (b32, plain) in vectors {
            XCTAssertEqual(TOTP.base32Decode(b32), Data(plain.utf8), b32)
        }
    }

    func testBase32_lenientToRealWorldInput_strictToGarbage() {
        // Minúsculas, espaços e hífens de agrupamento (como apps exibem) são aceitos…
        XCTAssertEqual(TOTP.base32Decode("mzxw 6ytb-oi"), Data("foobar".utf8))
        // …mas caractere fora do alfabeto (0, 1, 8, 9, símbolos) é rejeitado, não adivinhado.
        XCTAssertNil(TOTP.base32Decode("MZX0"))
        XCTAssertNil(TOTP.base32Decode("ABC!"))
    }

    // MARK: - Parâmetros fora de faixa (fail-closed)

    func testHOTP_rejectsBadParams() {
        XCTAssertNil(TOTP.hotp(secret: Data(), counter: 0))
        XCTAssertNil(TOTP.hotp(secret: sha1Key, counter: 0, digits: 5))
        XCTAssertNil(TOTP.hotp(secret: sha1Key, counter: 0, digits: 9))
        XCTAssertNil(TOTP.code(for: .init(secret: sha1Key, period: 0)))
    }

    func testSecondsRemaining_bounds() {
        // t=59 → resta 1 s da janela; t=60 → janela nova inteira (30).
        XCTAssertEqual(TOTP.secondsRemaining(at: Date(timeIntervalSince1970: 59)), 1)
        XCTAssertEqual(TOTP.secondsRemaining(at: Date(timeIntervalSince1970: 60)), 30)
        for t: TimeInterval in [0, 1, 29, 31, 12345] {
            let r = TOTP.secondsRemaining(at: Date(timeIntervalSince1970: t))
            XCTAssertTrue((1...30).contains(r), "t=\(t) → \(r)")
        }
    }

    // MARK: - otpauth:// (entrada hostil de QR)

    func testParse_fullURI() throws {
        let a = try XCTUnwrap(TOTP.parse(otpauthURI:
            "otpauth://totp/GitHub:ana%40exemplo.com?secret=MZXW6YTBOI&issuer=GitHub&digits=8&period=60&algorithm=SHA256"))
        XCTAssertEqual(a.secret, Data("foobar".utf8))
        XCTAssertEqual(a.issuer, "GitHub")
        XCTAssertEqual(a.label, "ana@exemplo.com")
        XCTAssertEqual(a.digits, 8)
        XCTAssertEqual(a.period, 60)
        XCTAssertEqual(a.algorithm, .sha256)
    }

    func testParse_minimalURI_defaults() throws {
        let a = try XCTUnwrap(TOTP.parse(otpauthURI: "otpauth://totp/conta?secret=MZXW6YTB"))
        XCTAssertEqual(a.label, "conta")
        XCTAssertEqual(a.issuer, "")
        XCTAssertEqual(a.digits, 6)
        XCTAssertEqual(a.period, 30)
        XCTAssertEqual(a.algorithm, .sha1)
    }

    /// Emissor no PATH ("Emissor:conta") vale quando não há parâmetro `issuer`; o parâmetro vence.
    func testParse_issuerFromPath_paramWins() throws {
        let fromPath = try XCTUnwrap(TOTP.parse(otpauthURI: "otpauth://totp/Aco:me?secret=MZXQ"))
        XCTAssertEqual(fromPath.issuer, "Aco")
        XCTAssertEqual(fromPath.label, "me")
        let paramWins = try XCTUnwrap(TOTP.parse(otpauthURI: "otpauth://totp/Aco:me?secret=MZXQ&issuer=Real"))
        XCTAssertEqual(paramWins.issuer, "Real")
    }

    func testParse_hostileInputs_rejected() {
        for bad in [
            "https://totp/x?secret=MZXQ",                       // scheme errado
            "otpauth://hotp/x?secret=MZXQ",                     // hotp (contador) fora do escopo
            "otpauth://totp/x",                                 // sem secret
            "otpauth://totp/x?secret=",                         // secret vazio
            "otpauth://totp/x?secret=MZX0",                     // Base32 inválido
            "otpauth://totp/x?secret=MZXQ&digits=9",            // digits fora da faixa
            "otpauth://totp/x?secret=MZXQ&period=0",            // período inválido
            "otpauth://totp/x?secret=MZXQ&algorithm=MD5",       // algoritmo desconhecido
        ] {
            XCTAssertNil(TOTP.parse(otpauthURI: bad), bad)
        }
    }

    /// Roundtrip completo: URI de QR real → conta → código do vetor RFC (t=59, chave do RFC em Base32).
    func testEndToEnd_qrToCode() throws {
        // "12345678901234567890" em Base32 = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        let a = try XCTUnwrap(TOTP.parse(otpauthURI:
            "otpauth://totp/Demo:rfc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
        XCTAssertEqual(a.secret, Data("12345678901234567890".utf8))
        XCTAssertEqual(TOTP.code(for: a, at: Date(timeIntervalSince1970: 59)), "287082")
    }
}
