import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Lógica de ingestão (o coração do bug C1, agora no núcleo e testável) + L12 (guards de senha vazia
/// secundários e IngestSeal defensivo).
@MainActor
final class IngestLogicTests: XCTestCase {

    // MARK: - Regra de "dono" da ingestão (tabela-verdade)

    func testOwnership_truthTable() {
        // Tem par guardado → sempre usa o seu (independe do que está publicado).
        XCTAssertEqual(IngestSeal.ownership(hasStoredKeypair: true, publishedPublicKeyValid: true), .useStored)
        XCTAssertEqual(IngestSeal.ownership(hasStoredKeypair: true, publishedPublicKeyValid: false), .useStored)
        // Sem par guardado + já há pública válida → OUTRO cofre é dono; não clobbera (regra do C1).
        XCTAssertEqual(IngestSeal.ownership(hasStoredKeypair: false, publishedPublicKeyValid: true), .deferToOther)
        // Sem par e sem pública válida → este cofre vira dono.
        XCTAssertEqual(IngestSeal.ownership(hasStoredKeypair: false, publishedPublicKeyValid: false), .becomeOwner)
    }

    // MARK: - Reconstrução do par a partir do blob guardado (sk||pk)

    func testKeypair_storedRoundTrip_reconstructsWorkingPair() throws {
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        XCTAssertEqual(kp.stored.count, 64)

        let kp2 = try XCTUnwrap(IngestSeal.keypair(fromStored: kp.stored))
        XCTAssertEqual(kp2, kp, "sk||pk reconstrói o par idêntico — sem depender do arquivo compartilhado")

        // E o par reconstruído ABRE o que foi selado para a pública (o ponto do C1).
        let sealed = try XCTUnwrap(IngestSeal.seal(Data("conteúdo".utf8), to: kp.publicKey))
        XCTAssertEqual(IngestSeal.open(sealed, keypair: kp2), Data("conteúdo".utf8))
    }

    func testKeypair_fromStored_wrongLength_isNil() {
        XCTAssertNil(IngestSeal.keypair(fromStored: Data(count: 63)))
        XCTAssertNil(IngestSeal.keypair(fromStored: Data(count: 65)))
        XCTAssertNil(IngestSeal.keypair(fromStored: Data()))
        XCTAssertNotNil(IngestSeal.keypair(fromStored: Data(count: 64)))
    }

    // MARK: - Isolamento: o decoy NÃO enxerga o segredo de ingestão do cofre real

    /// O BlobStore é compartilhado, mas a chave de armazenamento deriva da MK. O cofre falso, com MK
    /// diferente, não lê o segredo de ingestão guardado pelo real — a base do "dono" não vazar.
    func testIngestSecret_isolatedBetweenRealAndDecoy() throws {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 7, count: 32))))
        let (env0, realSession) = try vault.create(password: "real", kdf: .testFast())
        let blobs = InMemoryBlobStore()

        let realStore = try VaultStore(session: realSession, blobs: blobs)
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        try realStore.setIngestSecretKey(kp.stored)
        XCTAssertEqual(try realStore.ingestSecretKey(), kp.stored, "o real lê o próprio segredo")

        let (_, decoySession) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        let decoyStore = try VaultStore(session: decoySession, blobs: blobs)
        XCTAssertNil(try decoyStore.ingestSecretKey(), "o decoy NÃO enxerga o segredo de ingestão do real")
    }

    // MARK: - L12: guards de senha/frase vazia secundários

    private func freshVault() throws -> (Vault, VaultEnvelope) {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32))))
        let (env, _) = try vault.create(password: "real", kdf: .testFast())
        return (vault, env)
    }

    func testSetDecoy_emptyDecoyPassword_throwsEmptyPassword() throws {
        let (vault, env) = try freshVault()
        XCTAssertThrowsError(try vault.setDecoy(envelope: env, password: "real", decoyPassword: "")) {
            XCTAssertEqual($0 as? VaultError, .emptyPassword)
        }
    }

    func testAddRecovery_emptyPhrase_throwsEmptyPassword() throws {
        let (vault, env) = try freshVault()
        XCTAssertThrowsError(try vault.addRecovery(envelope: env, password: "real", recoveryPhrase: "", kdf: .testFast())) {
            XCTAssertEqual($0 as? VaultError, .emptyPassword)
        }
    }

    func testRecover_emptyNewPassword_throwsEmptyPassword() throws {
        let (vault, env) = try freshVault()
        XCTAssertThrowsError(try vault.recover(recoveryEnvelope: env, phrase: "x", newPassword: "", kdf: .testFast())) {
            XCTAssertEqual($0 as? VaultError, .emptyPassword)
        }
    }

    func testChangePassword_emptyNewPassword_throwsEmptyPassword() throws {
        let (vault, env) = try freshVault()
        // API pública guarda ANTES de derivar (não roda Argon2 à toa).
        XCTAssertThrowsError(try vault.changePassword(envelope: env, oldPassword: "real", newPassword: "")) {
            XCTAssertEqual($0 as? VaultError, .emptyPassword)
        }
    }

    // MARK: - L12: IngestSeal defensivo

    func testIngestSeal_open_truncated_returnsNil() throws {
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        XCTAssertNil(IngestSeal.open(Data([1, 2, 3]), keypair: kp), "sealed curto demais → nil, não estoura")
        XCTAssertNil(IngestSeal.open(Data(), keypair: kp))
    }

    func testIngestSeal_emptyMessage_roundTrips() throws {
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        let sealed = try XCTUnwrap(IngestSeal.seal(Data(), to: kp.publicKey))
        XCTAssertEqual(IngestSeal.open(sealed, keypair: kp), Data(), "mensagem vazia sela e abre")
    }
}
