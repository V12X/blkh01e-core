import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Testes que codificam as INVARIANTES de segurança — não só "funciona", mas "falha do jeito
/// certo". Usam `.testFast()` (KDF rápido) só para velocidade.
final class BlackHoleCoreTests: XCTestCase {

    private func newVault() -> Vault { Vault(device: SoftwareDeviceKeystore()) }
    private func fastCreate(_ vault: Vault, _ pw: String) throws -> (VaultEnvelope, VaultSession) {
        try vault.create(password: pw, kdf: .testFast())
    }

    /// Exige o MESMO erro unificado (não só "throws") — prova A2/indistinguibilidade.
    private func assertUnified(_ expr: () throws -> Void, _ msg: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try expr(), msg, file: file, line: line) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault, msg, file: file, line: line)
        }
    }

    // MARK: KDF

    func testKDF_deterministic_and_saltSensitive() throws {
        let salt = try KeyDerivation.newSalt()
        XCTAssertEqual(salt.count, KeyDerivation.saltLength)
        let a = try KeyDerivation.deriveKey(password: "correct horse", salt: salt, params: .testFast())
        let b = try KeyDerivation.deriveKey(password: "correct horse", salt: salt, params: .testFast())
        XCTAssertEqual(a, b)
        let c = try KeyDerivation.deriveKey(password: "correct horse", salt: try KeyDerivation.newSalt(), params: .testFast())
        XCTAssertNotEqual(a, c)
    }

    func testDeriveKey_rejectsBadSaltLength() {
        XCTAssertThrowsError(try KeyDerivation.deriveKey(password: "x", salt: [1, 2, 3], params: .testFast()))
    }

    // MARK: Round-trip

    func testCreateOpen_roundTrip() throws {
        let vault = newVault()
        let (env, s1) = try fastCreate(vault, "s3nha-forte")
        let (wf, ct) = try s1.encryptFile(Data("segredo".utf8), fileID: "item-1")
        let s2 = try vault.open(envelope: env, password: "s3nha-forte")
        XCTAssertEqual(try s2.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: "item-1"), Data("segredo".utf8))
    }

    /// Login "palavra + código": a senha final é a concatenação (ex.: `marimbondo45347012`). O núcleo
    /// aceita letras — quem barrava era só um guard de UI (removido). Abre com a combinação e NÃO com
    /// só o código (prova que a palavra faz parte da chave).
    func testCreateOpen_wordPlusDigits() throws {
        let vault = newVault()
        let (env, _) = try fastCreate(vault, "marimbondo45347012")
        XCTAssertNoThrow(try vault.open(envelope: env, password: "marimbondo45347012"))
        assertUnified({ _ = try vault.open(envelope: env, password: "45347012") }, "só o código não abre")
    }

    // MARK: A2 — TODOS os fracassos de open() retornam o MESMO erro

    func testAllOpenFailures_returnSameUnifiedError() throws {
        let vault = newVault()
        let (env, _) = try fastCreate(vault, "certa")

        assertUnified({ _ = try vault.open(envelope: env, password: "errada") }, "senha errada")
        assertUnified({ _ = try Vault(device: SoftwareDeviceKeystore()).open(envelope: env, password: "certa") }, "outro dispositivo")

        var shred = env; shred.slots = shred.slots.map { _ in Data() }
        assertUnified({ _ = try vault.open(envelope: shred, password: "certa") }, "crypto-shredado")

        var badSalt = env; badSalt.salt[0] ^= 0xFF
        assertUnified({ _ = try vault.open(envelope: badSalt, password: "certa") }, "salt adulterado (AAD)")

        var badVersion = env; badVersion.version = 99
        assertUnified({ _ = try vault.open(envelope: badVersion, password: "certa") }, "version adulterada")

        var badKDF = env; badKDF.kdf.opsLimit += 1
        assertUnified({ _ = try vault.open(envelope: badKDF, password: "certa") }, "params de KDF adulterados (AAD)")

        var badWrap = env
        for i in badWrap.slots.indices { badWrap.slots[i][badWrap.slots[i].count - 1] ^= 0xFF }
        assertUnified({ _ = try vault.open(envelope: badWrap, password: "certa") }, "MK embrulhada adulterada")
    }

    // MARK: B6 — erro tipado do fator-dispositivo (Face ID cancelado ≠ senha errada)

    func testDeviceAuthUnavailable_propagatesDistinctly() throws {
        struct AuthCancelKeystore: DeviceKeystore {
            func wrap(_ data: Data) throws -> Data { data }
            func unwrap(_ data: Data) throws -> Data { throw DeviceKeystoreError.authenticationCancelled }
        }
        let (env, _) = try fastCreate(newVault(), "certa")
        // Face ID cancelado é evento de UX distinto — NÃO deve virar .wrongPasswordOrNoVault.
        XCTAssertThrowsError(try Vault(device: AuthCancelKeystore()).open(envelope: env, password: "certa")) {
            XCTAssertEqual($0 as? VaultError, .deviceAuthUnavailable)
        }
    }

    /// B6 estendido: `setDecoy` e `changePassword` também honram o erro tipado — antes usavam
    /// `try? device.unwrap`, engolindo indisponibilidade do Enclave como "senha incorreta".
    func testDeviceAuthUnavailable_propagatesFromSetDecoyAndChangePassword() throws {
        struct AuthCancelKeystore: DeviceKeystore {
            func wrap(_ data: Data) throws -> Data { data }
            func unwrap(_ data: Data) throws -> Data { throw DeviceKeystoreError.authenticationCancelled }
        }
        let (env, _) = try fastCreate(newVault(), "certa")
        let brokenVault = Vault(device: AuthCancelKeystore())
        XCTAssertThrowsError(try brokenVault.setDecoy(envelope: env, password: "certa", decoyPassword: "falsa2")) {
            XCTAssertEqual($0 as? VaultError, .deviceAuthUnavailable)
        }
        XCTAssertThrowsError(try brokenVault.changePassword(envelope: env, oldPassword: "certa", newPassword: "nova2")) {
            XCTAssertEqual($0 as? VaultError, .deviceAuthUnavailable)
        }
    }

    // MARK: A1 — parâmetros de KDF vêm do envelope

    func testKDFParams_persistedInEnvelope() throws {
        let vault = newVault()
        let (env, _) = try fastCreate(vault, "s3nha")
        XCTAssertEqual(env.kdf, .testFast())
        XCTAssertNoThrow(try vault.open(envelope: env, password: "s3nha"))
    }

    // MARK: Persistência / unicidade

    func testTwoVaultsSamePassword_haveDifferentEnvelopes() throws {
        let v = newVault()
        let (e1, _) = try fastCreate(v, "mesma")
        let (e2, _) = try fastCreate(v, "mesma")
        XCTAssertNotEqual(e1.salt, e2.salt)
        XCTAssertNotEqual(e1.slots, e2.slots)
    }

    func testEnvelope_codableRoundTrip() throws {
        let (env, _) = try fastCreate(newVault(), "s3nha")
        let data = try JSONEncoder().encode(env)
        let decoded = try JSONDecoder().decode(VaultEnvelope.self, from: data)
        XCTAssertEqual(decoded, env)
    }

    // MARK: Troca de senha (M5)

    func testChangePassword_oldFailsNewWorks_sameData() throws {
        let vault = newVault()
        let (env, s) = try fastCreate(vault, "velha")
        let (wf, ct) = try s.encryptFile(Data("dado".utf8), fileID: "d1")
        let env2 = try vault.changePassword(envelope: env, oldPassword: "velha", newPassword: "nova", kdf: .testFast())
        assertUnified({ _ = try vault.open(envelope: env2, password: "velha") }, "senha antiga não abre mais")
        let s2 = try vault.open(envelope: env2, password: "nova")
        XCTAssertEqual(try s2.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: "d1"), Data("dado".utf8))
    }

    func testChangePassword_wrongOldPassword_fails() throws {
        let vault = newVault()
        let (env, _) = try fastCreate(vault, "velha")
        assertUnified({ _ = try vault.changePassword(envelope: env, oldPassword: "ERRADA", newPassword: "nova", kdf: .testFast()) }, "old errada")
    }

    // MARK: Cripto por-arquivo + fileID (B2)

    func testTamperedFileCiphertext_fails() throws {
        let (_, s) = try fastCreate(newVault(), "s3nha")
        var (wf, ct) = try s.encryptFile(Data("x".utf8), fileID: "a")
        ct[ct.count - 1] ^= 0xFF
        XCTAssertThrowsError(try s.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: "a"))
    }

    func testTamperedWrappedFileKey_fails() throws {
        let (_, s) = try fastCreate(newVault(), "s3nha")
        var (wf, ct) = try s.encryptFile(Data("x".utf8), fileID: "a")
        wf[wf.count - 1] ^= 0xFF
        XCTAssertThrowsError(try s.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: "a"))
    }

    func testFileID_isBound() throws {
        let (_, s) = try fastCreate(newVault(), "s3nha")
        let (wf, ct) = try s.encryptFile(Data("x".utf8), fileID: "file-A")
        XCTAssertEqual(try s.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: "file-A"), Data("x".utf8))
        // decifrar sob outro fileID (relocar entre slots) falha
        XCTAssertThrowsError(try s.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: "file-B"))
    }

    // MARK: Sessão

    func testSessionClosed_throwsDistinctError() throws {
        let (_, s) = try fastCreate(newVault(), "s3nha")
        let (wf, ct) = try s.encryptFile(Data("x".utf8), fileID: "a")
        s.close()
        XCTAssertFalse(s.isOpen)
        XCTAssertThrowsError(try s.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: "a")) {
            XCTAssertEqual($0 as? VaultError, .sessionClosed)
        }
        XCTAssertThrowsError(try s.encryptFile(Data("x".utf8), fileID: "a")) {
            XCTAssertEqual($0 as? VaultError, .sessionClosed)
        }
    }

    // MARK: create

    func testCreate_rejectsEmptyPassword() {
        XCTAssertThrowsError(try newVault().create(password: "")) {
            XCTAssertEqual($0 as? VaultError, .emptyPassword)
        }
    }

    // MARK: Boundary de persistência (regressão-decode)

    func testOpenFromEnvelopeData_roundTrip() throws {
        let vault = newVault()
        let (env, s1) = try fastCreate(vault, "s3nha")
        let (wf, ct) = try s1.encryptFile(Data("oi".utf8), fileID: "a")
        let data = try vault.encodeEnvelope(env)
        let s2 = try vault.open(fromEnvelopeData: data, password: "s3nha")
        XCTAssertEqual(try s2.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: "a"), Data("oi".utf8))
    }

    func testOpenFromEnvelopeData_corruptBlob_unified() {
        assertUnified({ _ = try self.newVault().open(fromEnvelopeData: Data([0x7b, 0x00, 0xff]), password: "x") }, "blob corrompido")
        assertUnified({ _ = try self.newVault().open(fromEnvelopeData: Data(), password: "x") }, "blob vazio")
    }

    // MARK: Força de KDF fixa em produção (regressão A3)

    func testPublicCreate_usesFixedStandardKDF() throws {
        let vault = newVault()
        let (env, _) = try vault.create(password: "s3nha-de-producao")
        XCTAssertEqual(env.kdf, .standard())
        XCTAssertNoThrow(try vault.open(envelope: env, password: "s3nha-de-producao"))
    }

    func testEnvelope_rejectsInsaneKDFParams() throws {
        let vault = newVault()
        var (env, _) = try fastCreate(vault, "s3nha")
        env.kdf.memLimit = Int.max
        assertUnified({ _ = try vault.open(envelope: env, password: "s3nha") }, "params de KDF fora de faixa")
    }
}
