import XCTest
@testable import BlackHoleCore

/// Importação do QR do Google Authenticator. O payload dos testes é montado por um ESCRITOR de
/// protobuf independente (abaixo) — o leitor é validado contra outra implementação, não contra
/// si mesmo.
final class TOTPMigrationTests: XCTestCase {

    // MARK: - Escritor mínimo (só para os testes)

    private func varint(_ v: UInt64) -> Data {
        var v = v, out = Data()
        repeat {
            var b = UInt8(v & 0x7F); v >>= 7
            if v != 0 { b |= 0x80 }
            out.append(b)
        } while v != 0
        return out
    }
    private func field(_ number: Int, varint v: UInt64) -> Data {
        varint(UInt64(number << 3 | 0)) + varint(v)
    }
    private func field(_ number: Int, bytes d: Data) -> Data {
        varint(UInt64(number << 3 | 2)) + varint(UInt64(d.count)) + d
    }
    private func field(_ number: Int, string s: String) -> Data { field(number, bytes: Data(s.utf8)) }

    /// Um `OtpParameters`. `type`: 1 = HOTP, 2 = TOTP.
    private func params(secret: Data, name: String, issuer: String,
                        algorithm: UInt64 = 1, digits: UInt64 = 1, type: UInt64 = 2) -> Data {
        field(1, bytes: secret) + field(2, string: name) + field(3, string: issuer)
            + field(4, varint: algorithm) + field(5, varint: digits) + field(6, varint: type)
    }

    private func payload(_ items: [Data], batchIndex: UInt64 = 0, batchSize: UInt64 = 1) -> Data {
        var d = Data()
        for i in items { d += field(1, bytes: i) }
        d += field(2, varint: 1)                       // version
        d += field(3, varint: batchSize)
        d += field(4, varint: batchIndex)
        return d
    }

    private func uri(_ payload: Data) -> String {
        let b64 = payload.base64EncodedString()
        let esc = b64.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? b64
        return "otpauth-migration://offline?data=\(esc)"
    }

    // MARK: - Casos

    func testParse_duasContas_comEmissorEDigitos() throws {
        let s1 = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        let s2 = Data(repeating: 0x41, count: 20)
        let p = payload([
            params(secret: s1, name: "ana@exemplo.com", issuer: "GitHub"),
            params(secret: s2, name: "conta2", issuer: "", algorithm: 2, digits: 2),
        ], batchIndex: 0, batchSize: 1)

        let r = try XCTUnwrap(TOTPMigration.parse(migrationURI: uri(p)))
        XCTAssertEqual(r.accounts.count, 2)
        XCTAssertEqual(r.skippedHOTP, 0)
        XCTAssertEqual(r.accounts[0].secret, s1)
        XCTAssertEqual(r.accounts[0].issuer, "GitHub")
        XCTAssertEqual(r.accounts[0].label, "ana@exemplo.com")
        XCTAssertEqual(r.accounts[0].digits, 6)
        XCTAssertEqual(r.accounts[0].algorithm, .sha1)
        XCTAssertEqual(r.accounts[1].secret, s2)
        XCTAssertEqual(r.accounts[1].digits, 8)
        XCTAssertEqual(r.accounts[1].algorithm, .sha256)
        XCTAssertEqual(r.accounts[1].period, 30)
    }

    /// HOTP é contado e ignorado (o cofre guarda TOTP) — a UI precisa poder dizer isso.
    func testParse_hotp_ignoradoEContado() throws {
        let p = payload([
            params(secret: Data(repeating: 1, count: 10), name: "a", issuer: "X"),
            params(secret: Data(repeating: 2, count: 10), name: "b", issuer: "Y", type: 1),
        ])
        let r = try XCTUnwrap(TOTPMigration.parse(migrationURI: uri(p)))
        XCTAssertEqual(r.accounts.count, 1)
        XCTAssertEqual(r.skippedHOTP, 1)
        XCTAssertEqual(r.accounts[0].label, "a")
    }

    /// O Google divide a exportação em vários QRs: o índice tem de chegar à UI.
    func testParse_loteDeVariosQRs() throws {
        let p = payload([params(secret: Data(repeating: 3, count: 10), name: "c", issuer: "Z")],
                        batchIndex: 1, batchSize: 3)
        let r = try XCTUnwrap(TOTPMigration.parse(migrationURI: uri(p)))
        XCTAssertEqual(r.batchIndex, 1)
        XCTAssertEqual(r.batchSize, 3)
    }

    /// Payload válido e VAZIO não é erro — é "não havia contas neste QR".
    func testParse_vazio_naoEhErro() throws {
        let r = try XCTUnwrap(TOTPMigration.parse(migrationURI: uri(payload([]))))
        XCTAssertTrue(r.accounts.isEmpty)
    }

    func testParse_entradasInvalidas() {
        XCTAssertNil(TOTPMigration.parse(migrationURI: "otpauth://totp/x?secret=ABCDEFGH"))  // esquema errado
        XCTAssertNil(TOTPMigration.parse(migrationURI: "otpauth-migration://offline"))        // sem data
        XCTAssertNil(TOTPMigration.parse(migrationURI: "otpauth-migration://offline?data=%%%")) // Base64 inválido
        XCTAssertNil(TOTPMigration.parse(payload: Data([0x0A, 0x7F])))                         // tamanho > buffer
        XCTAssertNil(TOTPMigration.parse(payload: Data([0x08])))                               // varint truncado
        // MD5 (algoritmo 4) não é suportado: recusa em vez de fingir SHA-1.
        XCTAssertNil(TOTPMigration.parse(payload: payload([
            params(secret: Data(repeating: 1, count: 10), name: "a", issuer: "X", algorithm: 4)])))
    }

    /// Um payload gigante de campo desconhecido não pode fazer o leitor alocar por um tamanho
    /// que o buffer não tem (entrada de QR é canal hostil).
    func testParse_tamanhoMentiroso_naoAloca() {
        var d = Data([0x0A])                    // campo 1, wire type 2
        d += Data([0xFF, 0xFF, 0xFF, 0xFF, 0x07])  // tamanho ~2 GB
        XCTAssertNil(TOTPMigration.parse(payload: d))
    }

    /// Conta → URI → conta: o que entra pelo QR de migração sai igual pelo caminho normal do app.
    func testOtpauthURI_roundTrip() throws {
        let a = TOTP.Account(secret: Data([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF]),
                             issuer: "GitHub", label: "ana@exemplo.com",
                             digits: 8, period: 60, algorithm: .sha256)
        let uri = TOTP.otpauthURI(for: a)
        let back = try XCTUnwrap(TOTP.parse(otpauthURI: uri))
        XCTAssertEqual(back, a)
    }

    func testBase32_roundTrip() throws {
        for n in 1...40 {
            let d = Data((0..<n).map { UInt8(($0 * 7 + 3) % 251) })
            let s = TOTP.base32Encode(d)
            XCTAssertEqual(TOTP.base32Decode(s), d, "falhou com \(n) bytes")
        }
    }

    /// O código gerado a partir da conta importada bate com o do URI equivalente — a importação
    /// não pode mudar o segredo pelo caminho.
    func testCodigoIgual_depoisDaImportacao() throws {
        let secret = Data("12345678901234567890".utf8)          // vetor do RFC 6238
        let p = payload([params(secret: secret, name: "rfc", issuer: "IETF")])
        let r = try XCTUnwrap(TOTPMigration.parse(migrationURI: uri(p)))
        let importada = try XCTUnwrap(r.accounts.first)
        let t = Date(timeIntervalSince1970: 59)
        XCTAssertEqual(TOTP.code(for: importada, at: t), "287082")
    }
}
