import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Testa a camada de gavetas: índice cifrado (blob único atômico), add/list/read, crypto-shred
/// no delete, move, persistência real, validações de contrato e chaves de blob derivadas da MK.
@MainActor
final class VaultStoreTests: XCTestCase {

    private func makeStore() throws -> (Vault, VaultEnvelope, InMemoryBlobStore, VaultStore, VaultSession) {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 7, count: 32))))
        let (env, session) = try vault.create(password: "s3nha", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        let store = try VaultStore(session: session, blobs: blobs)
        return (vault, env, blobs, store, session)
    }

    func testAddListRead() throws {
        let (_, _, _, store, _) = try makeStore()
        let foto = try store.add(content: Data("bytes-da-foto".utf8), kind: .photo, drawer: .photosVideos, name: "praia.jpg", createdAt: 1000, id: "id-foto")
        try store.add(content: Data("uma nota".utf8), kind: .text, drawer: .textsDocs, name: "nota", createdAt: 1001, id: "id-nota")
        try store.add(content: Data("https://exemplo.com".utf8), kind: .link, drawer: .links, name: "exemplo", createdAt: 1002, id: "id-link")

        XCTAssertEqual(store.items().count, 3)
        XCTAssertEqual(store.items(in: .photosVideos).map(\.id), ["id-foto"])
        XCTAssertEqual(store.items(in: .links).count, 1)
        XCTAssertEqual(try store.read(foto), Data("bytes-da-foto".utf8))
    }

    func testDelete_isCryptoShred() throws {
        let (_, _, blobs, store, session) = try makeStore()
        let item = try store.add(content: Data("segredo".utf8), kind: .text, drawer: .textsDocs, name: "x", createdAt: 1, id: "id-x")
        let ckey = try session.storageKey("content/id-x")
        XCTAssertNotNil(try blobs.get(ckey), "conteúdo presente sob a chave derivada da MK")

        try store.delete("id-x")
        XCTAssertTrue(store.items().isEmpty, "some do índice")
        XCTAssertNil(try blobs.get(ckey), "ciphertext apagado")
        XCTAssertThrowsError(try store.read(item), "sem a wrappedFileKey, o item é irrecuperável")
    }

    func testThumbnail_roundTrip_andDeletedWithItem() throws {
        let (_, _, blobs, store, session) = try makeStore()
        try store.add(content: Data("foto".utf8), kind: .photo, drawer: .photosVideos, name: "p.jpg", createdAt: 1, id: "id-p")
        let thumb = Data("miniatura-jpeg".utf8)
        try store.setThumbnail(thumb, for: "id-p")
        XCTAssertEqual(try store.thumbnail(for: "id-p"), thumb, "round-trip da miniatura cifrada")

        let tkey = try session.storageKey("thumb/id-p")
        XCTAssertNotNil(try blobs.get(tkey))
        try store.delete("id-p")
        XCTAssertNil(try store.thumbnail(for: "id-p"), "miniatura some junto com o item")
        XCTAssertNil(try blobs.get(tkey), "blob da miniatura apagado no delete")
    }

    func testThumbnail_isolatedBetweenRealAndDecoy() throws {
        // A miniatura deriva a chave de blob da MK: o decoy (outra MK) não lê a do real.
        let (vault, env, blobs, realStore, _) = try makeStore()
        try realStore.add(content: Data("foto".utf8), kind: .photo, drawer: .photosVideos, name: "p", createdAt: 1, id: "id-p")
        try realStore.setThumbnail(Data("thumb-real".utf8), for: "id-p")
        let (_, decoySession) = try vault.setDecoy(envelope: env, password: "s3nha", decoyPassword: "falsa")
        let decoyStore = try VaultStore(session: decoySession, blobs: blobs)
        XCTAssertNil(try decoyStore.thumbnail(for: "id-p"), "o decoy não enxerga a miniatura do real")
    }

    func testMove_betweenDrawers() throws {
        let (_, _, _, store, _) = try makeStore()
        try store.add(content: Data("d".utf8), kind: .document, drawer: .textsDocs, name: "doc", createdAt: 1, id: "id-d")
        try store.move("id-d", to: .photosVideos)
        XCTAssertTrue(store.items(in: .textsDocs).isEmpty)
        XCTAssertEqual(store.items(in: .photosVideos).map(\.id), ["id-d"])
    }

    func testRename_updatesNamePersistently_contentIntact() throws {
        let (vault, env, blobs, store, _) = try makeStore()
        let item = try store.add(content: Data("segredo".utf8), kind: .document, drawer: .textsDocs,
                                 name: "antigo", createdAt: 1, id: "id-r")
        try store.rename("id-r", to: "novo nome")
        XCTAssertEqual(store.items().first?.name, "novo nome")

        // Persiste: sessão nova relê o nome novo, e o conteúdo (AAD/id estáveis) segue legível.
        let store2 = try VaultStore(session: try vault.open(envelope: env, password: "s3nha"), blobs: blobs)
        XCTAssertEqual(store2.items().first?.name, "novo nome")
        XCTAssertEqual(try store2.read(store2.items().first!), Data("segredo".utf8))
        _ = item
    }

    func testRename_emptyName_rejected() throws {
        let (_, _, _, store, _) = try makeStore()
        try store.add(content: Data("x".utf8), kind: .text, drawer: .textsDocs, name: "n", createdAt: 1, id: "id-e")
        XCTAssertThrowsError(try store.rename("id-e", to: "   ")) {
            XCTAssertEqual($0 as? VaultError, .invalidArgument)
        }
    }

    func testRename_unknownId_rejected() throws {
        let (_, _, _, store, _) = try makeStore()
        XCTAssertThrowsError(try store.rename("nao-existe", to: "x")) {
            XCTAssertEqual($0 as? VaultError, .invalidArgument)
        }
    }

    func testPersistence_reopenWithFreshSession() throws {
        let (vault, env, blobs, store, _) = try makeStore()
        let item = try store.add(content: Data("persistido".utf8), kind: .text, drawer: .textsDocs, name: "n", createdAt: 5, id: "id-p")

        let session2 = try vault.open(envelope: env, password: "s3nha")
        let store2 = try VaultStore(session: session2, blobs: blobs)
        XCTAssertEqual(store2.items().map(\.id), ["id-p"], "índice persistiu cifrado e reabriu")
        XCTAssertEqual(try store2.read(item), Data("persistido".utf8))
    }

    func testWrongVault_cannotReadIndex() throws {
        let (_, _, blobs, store, _) = try makeStore()
        try store.add(content: Data("x".utf8), kind: .text, drawer: .textsDocs, name: "n", createdAt: 1, id: "id-x")
        let outro = Vault(device: SoftwareDeviceKeystore())
        let (_, sessionOutro) = try outro.create(password: "outra", kdf: .testFast())
        // Outra MK → chave de índice derivada diferente → nem enxerga o índice (store abre vazio).
        let storeOutro = try VaultStore(session: sessionOutro, blobs: blobs)
        XCTAssertTrue(storeOutro.items().isEmpty, "cofre alheio não enxerga o índice deste")
    }

    // MARK: Validações de contrato (A5/A7)

    func testAdd_rejectsDuplicateID() throws {
        let (_, _, _, store, _) = try makeStore()
        try store.add(content: Data("1".utf8), kind: .text, drawer: .textsDocs, name: "a", createdAt: 1, id: "dup")
        XCTAssertThrowsError(try store.add(content: Data("2".utf8), kind: .text, drawer: .textsDocs, name: "b", createdAt: 2, id: "dup")) {
            XCTAssertEqual($0 as? VaultError, .invalidArgument)
        }
        XCTAssertEqual(store.items().count, 1, "id duplicado não entra")
    }

    func testAdd_rejectsEmptyIDorName_andNonFiniteDate() throws {
        let (_, _, _, store, _) = try makeStore()
        XCTAssertThrowsError(try store.add(content: Data(), kind: .text, drawer: .textsDocs, name: "a", createdAt: 1, id: ""))
        XCTAssertThrowsError(try store.add(content: Data(), kind: .text, drawer: .textsDocs, name: "", createdAt: 1, id: "x"))
        XCTAssertThrowsError(try store.add(content: Data(), kind: .text, drawer: .textsDocs, name: "a", createdAt: .nan, id: "y"))
        XCTAssertThrowsError(try store.add(content: Data(), kind: .text, drawer: .textsDocs, name: "a", createdAt: .infinity, id: "z"))
        XCTAssertTrue(store.items().isEmpty, "nenhuma entrada inválida foi persistida")
    }

    // MARK: Chave secreta de ingestão (sob a MK)

    func testIngestSecretKey_persistsUnderMK() throws {
        let (vault, env, blobs, store, _) = try makeStore()
        let kp = try XCTUnwrap(IngestSeal.newKeypair())
        XCTAssertNil(try store.ingestSecretKey(), "começa sem chave de ingestão")
        try store.setIngestSecretKey(kp.secretKey)
        XCTAssertEqual(try store.ingestSecretKey(), kp.secretKey)

        // persiste e reabre numa sessão nova
        let store2 = try VaultStore(session: try vault.open(envelope: env, password: "s3nha"), blobs: blobs)
        let recovered = try XCTUnwrap(try store2.ingestSecretKey())
        // um blob selado para a pública abre com o par reconstituído (pub em claro + secret recuperada)
        let sealed = try XCTUnwrap(IngestSeal.seal(Data("do zap".utf8), to: kp.publicKey))
        let opened = IngestSeal.open(sealed, keypair: .init(publicKey: kp.publicKey, secretKey: recovered))
        XCTAssertEqual(opened, Data("do zap".utf8))
    }

    // MARK: Chaves derivadas — id que imita chave interna não colide

    func testReservedLikeID_doesNotCorruptIndex() throws {
        let (_, _, _, store, _) = try makeStore()
        // As chaves de blob são HMAC(MK, rótulo); um id que imita um rótulo interno cai em
        // "content/<id>" e nunca coincide com "index"/"ingest". Sem colisão possível.
        try store.add(content: Data("ok".utf8), kind: .text, drawer: .textsDocs, name: "n", createdAt: 1, id: "index")
        try store.add(content: Data("real".utf8), kind: .text, drawer: .textsDocs, name: "m", createdAt: 2, id: "ingest")
        XCTAssertEqual(store.items().count, 2, "índice intacto apesar do id malicioso")
    }

    // MARK: Frase do backup automático (cifrada sob a MK)

    func testBackupPhrase_roundTripAndDelete() throws {
        let (_, _, _, store, _) = try makeStore()
        XCTAssertNil(try store.backupPhrase(), "sem frase até ativar")
        try store.setBackupPhrase("doze palavras fortes de exemplo")
        XCTAssertEqual(try store.backupPhrase(), "doze palavras fortes de exemplo")
        try store.deleteBackupPhrase()
        XCTAssertNil(try store.backupPhrase(), "desativar apaga a frase")
    }

    func testAutoFillFlag_roundTrip() throws {
        let (_, _, _, store, _) = try makeStore()
        XCTAssertFalse(try store.autoFillEnabled(), "desligado por padrão")
        try store.setAutoFillEnabled(true)
        XCTAssertTrue(try store.autoFillEnabled())
        try store.setAutoFillEnabled(false)
        XCTAssertFalse(try store.autoFillEnabled(), "desligar apaga o marcador")
    }

    func testBackupPhrase_doesNotTravelInArchive() throws {
        // O backup NUNCA carrega a própria chave: o export leva só blobs alcançáveis pelo índice
        // de itens — a frase (blob de rótulo derivado) fica de fora do arquivo.
        let (_, _, _, store, session) = try makeStore()
        try store.add(content: Data("conteudo".utf8), kind: .text, drawer: .textsDocs,
                      name: "n", createdAt: 1, id: "id-1")
        try store.setBackupPhrase("frase-do-backup-nao-viaja")
        let archive = try store.exportArchive(passphrase: "frase-do-backup-nao-viaja")
        XCTAssertFalse(archive.contains(subdata: Data("frase-do-backup-nao-viaja".utf8)),
                       "a frase não pode aparecer no arquivo (nem em claro)")
        // E o blob da frase (ciphertext) também não é levado: restaurar noutro aparelho não a
        // ressuscita (mesma MK → mesma chave de blob derivada; o get tem de dar nil).
        let blobs2 = InMemoryBlobStore()
        _ = try VaultArchive.restore(archive, passphrase: "frase-do-backup-nao-viaja", into: blobs2,
                                     device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32))),
                                     newPassword: "nova-senha-12", kdf: .testFast())
        let key = try session.storageKey("backup-phrase")
        XCTAssertNil(try blobs2.get(key), "blob da frase fora do arquivo restaurado")
    }
}

private extension Data {
    /// Busca ingênua de sub-sequência (suficiente para teste).
    func contains(subdata needle: Data) -> Bool {
        guard !needle.isEmpty, count >= needle.count else { return false }
        return (0...(count - needle.count)).contains { i in
            self.subdata(in: i..<i + needle.count) == needle
        }
    }
}
