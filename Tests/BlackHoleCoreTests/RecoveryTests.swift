import XCTest
import CryptoKit
@testable import BlackHoleCore

final class RecoveryTests: XCTestCase {

    private func vault() -> Vault { Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32)))) }

    func testRecovery_recoversData_andResetsPassword() throws {
        let v = vault()
        let (env, s1) = try v.create(password: "senha-antiga", kdf: .testFast())
        let (wf, ct) = try s1.encryptFile(Data("segredo".utf8), fileID: "x")

        // habilita recuperação
        let recEnv = try v.addRecovery(envelope: env, password: "senha-antiga", recoveryPhrase: "frase de recuperacao secreta", kdf: .testFast())

        // recupera com a frase + senha nova
        let (newMain, s2) = try v.recover(recoveryEnvelope: recEnv, phrase: "frase de recuperacao secreta", newPassword: "senha-nova", kdf: .testFast())

        // mesma MK: o dado antigo decifra na sessão recuperada
        XCTAssertEqual(try s2.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: "x"), Data("segredo".utf8))
        // novo envelope abre com a senha nova, não com a antiga
        XCTAssertNoThrow(try v.open(envelope: newMain, password: "senha-nova"))
        XCTAssertThrowsError(try v.open(envelope: newMain, password: "senha-antiga")) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }

    func testRecovery_wrongPhrase_fails() throws {
        let v = vault()
        let (env, _) = try v.create(password: "pw", kdf: .testFast())
        let recEnv = try v.addRecovery(envelope: env, password: "pw", recoveryPhrase: "frase certa", kdf: .testFast())
        XCTAssertThrowsError(try v.recover(recoveryEnvelope: recEnv, phrase: "frase errada", newPassword: "nova", kdf: .testFast())) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }

    func testAddRecovery_wrongPassword_fails() throws {
        let v = vault()
        let (env, _) = try v.create(password: "certa", kdf: .testFast())
        XCTAssertThrowsError(try v.addRecovery(envelope: env, password: "errada", recoveryPhrase: "frase", kdf: .testFast())) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }
}
