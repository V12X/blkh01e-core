import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Limites EXATOS (L9–L11): onde off-by-one ou overflow moram. Cobre os caps de tamanho do
/// SecureMessage no limite, o `unpad` com comprimento forjado, e as bordas de `withinSaneBounds`.
final class BoundaryTests: XCTestCase {

    // Espelham as constantes PRIVADAS do SecureMessage — se mudarem lá, atualizar aqui.
    private let maxTokenBytes = 1_048_576
    private let maxArmoredBytes = 2_000_000

    // MARK: - L9: caps de tamanho no limite exato

    func testExtractToken_atMaxTokenBytes_accepted() {
        // Token com EXATAMENTE o teto: "BLKH01E.1." (10) + N chars, N = teto-10.
        let token = "BLKH01E.1." + String(repeating: "A", count: maxTokenBytes - 10)
        XCTAssertEqual(token.utf8.count, maxTokenBytes)
        XCTAssertEqual(SecureMessage.extractToken(from: token)?.utf8.count, maxTokenBytes)
    }

    func testExtractToken_onePastMaxTokenBytes_rejected() {
        let token = "BLKH01E.1." + String(repeating: "A", count: maxTokenBytes - 10 + 1)
        XCTAssertEqual(token.utf8.count, maxTokenBytes + 1)
        XCTAssertNil(SecureMessage.extractToken(from: token), "1 byte além do teto de token → nil")
    }

    func testExtractToken_armoredAtMax_accepted() {
        // Texto com o teto ARMORED exato, com um token pequeno embutido (isola o cap de texto).
        let inner = "BLKH01E.1.AAAA"
        let text = String(repeating: " ", count: maxArmoredBytes - inner.utf8.count) + inner
        XCTAssertEqual(text.utf8.count, maxArmoredBytes)
        XCTAssertEqual(SecureMessage.extractToken(from: text), inner)
    }

    func testExtractToken_onePastMaxArmored_rejected() {
        let inner = "BLKH01E.1.AAAA"
        let text = String(repeating: " ", count: maxArmoredBytes - inner.utf8.count + 1) + inner
        XCTAssertEqual(text.utf8.count, maxArmoredBytes + 1)
        XCTAssertNil(SecureMessage.extractToken(from: text), "1 byte além do teto armored → nil")
    }

    // MARK: - L10: unpad com comprimento FORJADO além do buffer

    /// Quem tem a senha (segredo compartilhado) pode selar um corpo "padded" com um campo de
    /// comprimento mentiroso. `unpad` tem de recusar (fail-closed), nunca ler fora dos limites.
    /// Constrói o header do formato de fio v1 CONGELADO à mão — se o layout mudar, este teste muda.
    func testDecrypt_forgedPadLengthBeyondBuffer_failsClosed() throws {
        let password = "senha-compartilhada"
        let params = KDFParams.testFast()
        let salt = try KeyDerivation.newSalt()
        let key = try KeyDerivation.deriveKey(password: password, salt: salt, params: params)

        var header = Data("BH01".utf8)
        header.append(1)                                  // version
        header.append(1)                                  // mode = senha
        appendU32(&header, UInt32(params.opsLimit))
        appendU32(&header, UInt32(params.memLimit))
        header.append(contentsOf: salt)
        XCTAssertEqual(header.count, 30)

        var body = Data()
        appendU32(&body, 0xFFFF_FFFF)                     // len mentiroso, muito além do buffer
        body.append(Data(count: 256 - body.count))        // completa 1 bloco de padding
        let sealed = try AEAD.seal(body, key: key, aad: header)   // AEAD VÁLIDO → passa do open

        let armored = "BLKH01E.1." + b64url(header + sealed)
        XCTAssertThrowsError(try SecureMessage.decrypt(armored, password: password)) {
            XCTAssertEqual($0 as? MessageError, .wrongPasswordOrCorrupt, "unpad recusa, não estoura")
        }
    }

    // MARK: - L11: bordas de withinSaneBounds

    func testWithinSaneBounds_atSensitiveCeiling_true() {
        XCTAssertTrue(KDFParams.sensitive().withinSaneBounds(), "topo da faixa é válido")
    }

    func testWithinSaneBounds_oneBelowInteractiveFloor_false() {
        var belowOps = KDFParams.testFast()               // testFast = piso Interactive
        belowOps.opsLimit -= 1
        XCTAssertFalse(belowOps.withinSaneBounds(), "1 abaixo do piso de ops → inválido")

        var belowMem = KDFParams.testFast()
        belowMem.memLimit -= 1
        XCTAssertFalse(belowMem.withinSaneBounds(), "1 abaixo do piso de mem → inválido")
    }

    func testDeriveKey_belowFloor_throws() {
        var below = KDFParams.testFast()
        below.opsLimit -= 1
        let salt = (try? KeyDerivation.newSalt()) ?? [UInt8](repeating: 0, count: 16)
        XCTAssertThrowsError(try KeyDerivation.deriveKey(password: "x", salt: salt, params: below)) {
            XCTAssertEqual($0 as? VaultError, .keyDerivationFailed)
        }
    }

    /// Envelope com KDF abaixo do piso cai no guard de `unlockMasterKey` → erro unificado (via
    /// `decoyWork`), não deriva com params inválidos.
    @MainActor
    func testOpen_envelopeKDFBelowFloor_unified() throws {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32))))
        let (env0, _) = try vault.create(password: "real", kdf: .testFast())
        var env = env0
        env.kdf.opsLimit -= 1                              // abaixo do piso Interactive
        XCTAssertThrowsError(try vault.open(envelope: env, password: "real")) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }

    // MARK: - Helpers

    private func appendU32(_ d: inout Data, _ v: UInt32) {
        var be = v.bigEndian
        withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
    }
    private func b64url(_ d: Data) -> String {
        d.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
