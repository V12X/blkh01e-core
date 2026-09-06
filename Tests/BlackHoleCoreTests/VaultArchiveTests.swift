import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Arquivo portátil `.blkh01e`: round-trip real (outro aparelho = outro DeviceKeystore), erro único
/// nas falhas, e a invariante de deniabilidade (o export NÃO leva o cofre falso junto).
@MainActor
final class VaultArchiveTests: XCTestCase {

    /// "Aparelho A" e "aparelho B" = keystores diferentes. O arquivo tem de atravessar isso —
    /// é o ponto da feature.
    private func deviceA() -> DeviceKeystore { SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 0xA1, count: 32))) }
    private func deviceB() -> DeviceKeystore { SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 0xB2, count: 32))) }

    /// Cofre semeado no "aparelho A".
    private func seededVaultA() throws -> (Vault, VaultSession, VaultStore, InMemoryBlobStore) {
        let vault = Vault(device: deviceA())
        let (_, session) = try vault.create(password: "senha-real", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        let store = try VaultStore(session: session, blobs: blobs)
        try store.add(content: Data("dossiê".utf8), kind: .text, drawer: .textsDocs, name: "nota", createdAt: 1, id: "i1")
        try store.add(content: Data(repeating: 0x7F, count: 5000), kind: .photo, drawer: .photosVideos, name: "foto.jpg", createdAt: 2, id: "i2")
        return (vault, session, store, blobs)
    }

    // MARK: - Round-trip

    func testExportRestore_onAnotherDevice_contentSurvives() throws {
        let (_, session, store, blobs) = try seededVaultA()
        let archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "frase-do-arquivo", params: .testFast())

        // Aparelho B: BlobStore vazio, keystore diferente, senha nova.
        let blobsB = InMemoryBlobStore()
        let (envB, sessionB) = try VaultArchive.restore(archive, passphrase: "frase-do-arquivo",
                                                        into: blobsB, device: deviceB(),
                                                        newPassword: "senha-nova", kdf: .testFast())
        let storeB = try VaultStore(session: sessionB, blobs: blobsB)
        XCTAssertEqual(Set(storeB.items().map(\.name)), ["nota", "foto.jpg"])
        XCTAssertEqual(try storeB.read(storeB.items().first { $0.id == "i1" }!), Data("dossiê".utf8))
        XCTAssertEqual(try storeB.read(storeB.items().first { $0.id == "i2" }!), Data(repeating: 0x7F, count: 5000))

        // O envelope novo é do aparelho B: abre com a senha nova, no keystore de B.
        let vaultB = Vault(device: deviceB())
        XCTAssertNoThrow(try vaultB.open(envelope: envB, password: "senha-nova"))
    }

    /// O envelope importado é atado ao keystore de B: o de A não abre (fator-dispositivo vale).
    func testRestore_envelopeIsBoundToImportingDevice() throws {
        let (_, session, store, blobs) = try seededVaultA()
        let archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        let (envB, _) = try VaultArchive.restore(archive, passphrase: "f", into: InMemoryBlobStore(),
                                                 device: deviceB(), newPassword: "nova", kdf: .testFast())
        let vaultA = Vault(device: deviceA())
        XCTAssertThrowsError(try vaultA.open(envelope: envB, password: "nova")) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }

    /// Streaming para arquivo: mesmo formato (mesmo tamanho total), pico de memória ~um blob.
    /// Restaura do arquivo noutro aparelho e o conteúdo sobrevive.
    func testExportToFile_streams_sameFormat_restores() throws {
        let (_, session, store, blobs) = try seededVaultA()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("bh-\(UUID().uuidString).blkh01e")
        defer { try? FileManager.default.removeItem(at: url) }
        try VaultArchive.export(session: session, items: store.items(), blobs: blobs,
                                passphrase: "f", params: .testFast(), to: url)
        let fromFile = try Data(contentsOf: url)
        let fromData = try VaultArchive.export(session: session, items: store.items(), blobs: blobs,
                                               passphrase: "f", params: .testFast())
        XCTAssertEqual(fromFile.count, fromData.count, "mesmo layout → mesmo tamanho")
        XCTAssertEqual(fromFile.prefix(4), Data("BHA1".utf8))

        let blobsB = InMemoryBlobStore()
        let (_, sessionB) = try VaultArchive.restore(fromFile, passphrase: "f", into: blobsB,
                                                     device: deviceB(), newPassword: "n", kdf: .testFast())
        let storeB = try VaultStore(session: sessionB, blobs: blobsB)
        XCTAssertEqual(try storeB.read(storeB.items().first { $0.id == "i1" }!), Data("dossiê".utf8))
        XCTAssertEqual(try storeB.read(storeB.items().first { $0.id == "i2" }!), Data(repeating: 0x7F, count: 5000))
    }

    /// Falha no meio (frase vazia) não deixa arquivo pela metade.
    func testExportToFile_failure_leavesNoFile() throws {
        let (_, session, store, blobs) = try seededVaultA()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("bh-\(UUID().uuidString).blkh01e")
        XCTAssertThrowsError(try VaultArchive.export(session: session, items: store.items(), blobs: blobs,
                                                     passphrase: "", params: .testFast(), to: url))
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    func testExport_emptyVault_roundTrips() throws {
        let vault = Vault(device: deviceA())
        let (_, session) = try vault.create(password: "p", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        let store = try VaultStore(session: session, blobs: blobs)
        let archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        let blobsB = InMemoryBlobStore()
        let (_, sessionB) = try VaultArchive.restore(archive, passphrase: "f", into: blobsB,
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())
        let storeB = try VaultStore(session: sessionB, blobs: blobsB)
        XCTAssertTrue(storeB.items().isEmpty)
    }

    // MARK: - DENIABILIDADE (a invariante que não pode quebrar)

    /// O BlobStore é COMPARTILHADO entre real e falso. Exportar o real não pode levar nem um byte
    /// do falso — senão quem tem o arquivo + a frase vê blobs órfãos = prova de que há 2º cofre.
    func testExportReal_doesNotCarryDecoyBlobs() throws {
        let vault = Vault(device: deviceA())
        let (env0, realSession) = try vault.create(password: "real", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        let realStore = try VaultStore(session: realSession, blobs: blobs)
        try realStore.add(content: Data("segredo real".utf8), kind: .text, drawer: .textsDocs, name: "real", createdAt: 1, id: "r1")

        // Decoy com conteúdo próprio no MESMO BlobStore.
        let (_, decoySession) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        let decoyStore = try VaultStore(session: decoySession, blobs: blobs)
        try decoyStore.add(content: Data("lista de compras do decoy".utf8), kind: .text, drawer: .textsDocs, name: "falso", createdAt: 2, id: "d1")

        let archive = try VaultArchive.export(session: realSession, items: realStore.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())

        // 1) O arquivo não contém, em lugar nenhum, o ciphertext do blob do decoy.
        let decoyBlobKey = try decoySession.storageKey("content/d1")
        let decoyCiphertext = try XCTUnwrap(try blobs.get(decoyBlobKey))
        XCTAssertFalse(archive.range(of: decoyCiphertext) != nil, "ciphertext do decoy vazou para o arquivo")

        // 2) Nem o índice do decoy.
        let decoyIndex = try XCTUnwrap(try blobs.get(try decoySession.storageKey("index")))
        XCTAssertFalse(archive.range(of: decoyIndex) != nil, "índice do decoy vazou para o arquivo")

        // 3) Restaurado, o cofre tem só o conteúdo real — e a senha do decoy não abre nada.
        let blobsB = InMemoryBlobStore()
        let (envB, sessionB) = try VaultArchive.restore(archive, passphrase: "f", into: blobsB,
                                                         device: deviceB(), newPassword: "nova", kdf: .testFast())
        let storeB = try VaultStore(session: sessionB, blobs: blobsB)
        XCTAssertEqual(storeB.items().map(\.name), ["real"])
        let vaultB = Vault(device: deviceB())
        XCTAssertThrowsError(try vaultB.open(envelope: envB, password: "falsa"), "decoy não viaja no arquivo")
    }

    /// Exportar o DECOY produz um arquivo válido e indistinguível de um export "normal" — o arquivo
    /// é o retrato de UM cofre e não diz qual.
    func testExportDecoy_isAValidArchiveOfItsOwn() throws {
        let vault = Vault(device: deviceA())
        let (env0, realSession) = try vault.create(password: "real", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        let realStore = try VaultStore(session: realSession, blobs: blobs)
        try realStore.add(content: Data("segredo real".utf8), kind: .text, drawer: .textsDocs, name: "real", createdAt: 1, id: "r1")
        let (_, decoySession) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        let decoyStore = try VaultStore(session: decoySession, blobs: blobs)
        try decoyStore.add(content: Data("compras".utf8), kind: .text, drawer: .textsDocs, name: "falso", createdAt: 2, id: "d1")

        let archive = try VaultArchive.export(session: decoySession, items: decoyStore.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        let blobsB = InMemoryBlobStore()
        let (_, sessionB) = try VaultArchive.restore(archive, passphrase: "f", into: blobsB,
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())
        let storeB = try VaultStore(session: sessionB, blobs: blobsB)
        XCTAssertEqual(storeB.items().map(\.name), ["falso"], "o export do decoy contém só o decoy")
    }

    // MARK: - Falhas

    func testRestore_wrongPassphrase_unifiedError() throws {
        let (_, session, store, blobs) = try seededVaultA()
        let archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "certa", params: .testFast())
        XCTAssertThrowsError(try VaultArchive.restore(archive, passphrase: "errada", into: InMemoryBlobStore(),
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())) {
            XCTAssertEqual($0 as? ArchiveError, .wrongPassphraseOrCorrupt)
        }
    }

    func testRestore_tamperedBody_fails() throws {
        let (_, session, store, blobs) = try seededVaultA()
        var archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        archive[40] ^= 0xFF   // dentro da MK embrulhada
        XCTAssertThrowsError(try VaultArchive.restore(archive, passphrase: "f", into: InMemoryBlobStore(),
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())) {
            XCTAssertEqual($0 as? ArchiveError, .wrongPassphraseOrCorrupt)
        }
    }

    func testRestore_tamperedHeaderSalt_fails() throws {
        let (_, session, store, blobs) = try seededVaultA()
        var archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        archive[14] ^= 0x01   // salt dentro do header (que é AAD)
        XCTAssertThrowsError(try VaultArchive.restore(archive, passphrase: "f", into: InMemoryBlobStore(),
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())) {
            XCTAssertEqual($0 as? ArchiveError, .wrongPassphraseOrCorrupt)
        }
    }

    func testRestore_badMagic_malformed() throws {
        let (_, session, store, blobs) = try seededVaultA()
        var archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        archive[0] = 0x58
        XCTAssertThrowsError(try VaultArchive.restore(archive, passphrase: "f", into: InMemoryBlobStore(),
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())) {
            XCTAssertEqual($0 as? ArchiveError, .malformed)
        }
    }

    func testRestore_unknownVersion_unsupported() throws {
        let (_, session, store, blobs) = try seededVaultA()
        var archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        archive[4] = 99
        XCTAssertThrowsError(try VaultArchive.restore(archive, passphrase: "f", into: InMemoryBlobStore(),
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())) {
            XCTAssertEqual($0 as? ArchiveError, .unsupportedVersion)
        }
    }

    func testRestore_truncated_malformed() throws {
        let (_, session, store, blobs) = try seededVaultA()
        let archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        let cut = archive.subdata(in: 0..<(archive.count / 2))
        XCTAssertThrowsError(try VaultArchive.restore(cut, passphrase: "f", into: InMemoryBlobStore(),
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast()))
    }

    func testRestore_tinyGarbage_malformed() {
        XCTAssertThrowsError(try VaultArchive.restore(Data([1, 2, 3]), passphrase: "f", into: InMemoryBlobStore(),
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())) {
            XCTAssertEqual($0 as? ArchiveError, .malformed)
        }
    }

    /// Params de KDF forjados ACIMA de `.standard()` → recusa (anti-DoS de alocação no Argon2id).
    func testRestore_forgedKDFAboveStandard_malformed() throws {
        let (_, session, store, blobs) = try seededVaultA()
        var archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        // memLimit = 0xFFFFFFFF nos bytes 10..14
        archive[10] = 0xFF; archive[11] = 0xFF; archive[12] = 0xFF; archive[13] = 0xFF
        XCTAssertThrowsError(try VaultArchive.restore(archive, passphrase: "f", into: InMemoryBlobStore(),
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())) {
            XCTAssertEqual($0 as? ArchiveError, .malformed)
        }
    }

    func testExport_emptyPassphrase_rejected() throws {
        let (_, session, store, blobs) = try seededVaultA()
        XCTAssertThrowsError(try VaultArchive.export(session: session, items: store.items(),
                                                     blobs: blobs, passphrase: "", params: .testFast())) {
            XCTAssertEqual($0 as? ArchiveError, .emptyPassphrase)
        }
    }

    /// A frase do arquivo é INDEPENDENTE da senha do cofre: a senha do cofre de origem não abre
    /// o arquivo (e vice-versa).
    func testArchivePassphrase_isIndependentFromVaultPassword() throws {
        let (_, session, store, blobs) = try seededVaultA()
        let archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "frase-do-arquivo", params: .testFast())
        XCTAssertThrowsError(try VaultArchive.restore(archive, passphrase: "senha-real", into: InMemoryBlobStore(),
                                                      device: deviceB(), newPassword: "nova", kdf: .testFast())) {
            XCTAssertEqual($0 as? ArchiveError, .wrongPassphraseOrCorrupt)
        }
    }

    /// O plaintext NÃO pode aparecer em claro no arquivo (paranoia barata contra erro de montagem).
    func testArchive_containsNoPlaintext() throws {
        let (_, session, store, blobs) = try seededVaultA()
        let archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())
        XCTAssertNil(archive.range(of: Data("dossiê".utf8)), "conteúdo em claro no arquivo")
        XCTAssertNil(archive.range(of: Data("nota".utf8)), "nome de item em claro no arquivo")
        XCTAssertNil(archive.range(of: Data("content/i1".utf8)), "rótulo lógico em claro no arquivo")
    }
}
