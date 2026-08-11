import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Busca Privada (fase 1): texto extraído por item — blob próprio sob a MK, crypto-shred junto com
/// o item, fora do arquivo portátil; escopos de indexação opt-out persistidos sob a MK.
@MainActor
final class ExtractedTextTests: XCTestCase {

    private func makeStore() throws -> (VaultStore, VaultSession, InMemoryBlobStore) {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 7, count: 32))))
        let (_, session) = try vault.create(password: "s3nha", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        let store = try VaultStore(session: session, blobs: blobs)
        return (store, session, blobs)
    }

    // MARK: - Texto extraído

    func testRoundTrip_andEmptyMeansProcessed() throws {
        let (store, _, _) = try makeStore()
        try store.add(content: Data([0xFF]), kind: .photo, drawer: .photosVideos, name: "foto",
                      createdAt: 1, id: "a")
        XCTAssertNil(try store.extractedText(for: "a"))
        XCTAssertFalse(store.hasExtractedText(for: "a"))

        try store.setExtractedText("CONTRATO DE ALUGUEL — R$ 2.400", for: "a")
        XCTAssertEqual(try store.extractedText(for: "a"), "CONTRATO DE ALUGUEL — R$ 2.400")
        XCTAssertTrue(store.hasExtractedText(for: "a"))

        // String vazia = "processado, nada legível": persiste e é distinguível de "nunca processado".
        try store.setExtractedText("", for: "a")
        XCTAssertEqual(try store.extractedText(for: "a"), "")
        XCTAssertTrue(store.hasExtractedText(for: "a"))
    }

    func testUnknownID_throws_noOrphanBlob() throws {
        let (store, session, blobs) = try makeStore()
        XCTAssertThrowsError(try store.setExtractedText("x", for: "fantasma"))
        let key = try session.storageKey(VaultStore.extractLabel("fantasma"))
        XCTAssertNil(try blobs.get(key), "id fora do índice não pode deixar blob órfão")
    }

    func testDelete_shredsExtractedText() throws {
        let (store, session, blobs) = try makeStore()
        try store.add(content: Data([1]), kind: .document, drawer: .textsDocs, name: "doc",
                      createdAt: 1, id: "d")
        try store.setExtractedText("segredo extraído", for: "d")
        let key = try session.storageKey(VaultStore.extractLabel("d"))
        XCTAssertNotNil(try blobs.get(key))

        try store.delete("d")
        XCTAssertNil(try blobs.get(key), "texto extraído morre junto com o item")
        XCTAssertFalse(store.hasExtractedText(for: "d"))
    }

    func testPurgeExpired_shredsExtractedText() throws {
        let (store, session, blobs) = try makeStore()
        try store.add(content: Data([1]), kind: .photo, drawer: .photosVideos, name: "temp",
                      createdAt: 1000, id: "t", expiresAt: 2000)
        try store.setExtractedText("efêmero", for: "t")
        let key = try session.storageKey(VaultStore.extractLabel("t"))

        XCTAssertEqual(try store.purgeExpired(now: 2000), 1)
        XCTAssertNil(try blobs.get(key), "TTL crypto-shreda o texto extraído junto")
    }

    /// O `.blkh01e` leva só blobs alcançáveis pelo índice de itens — o texto extraído (regenerável)
    /// NÃO viaja. O conteúdo do item viaja normalmente.
    func testArchive_doesNotCarryExtractedText() throws {
        let (store, _, _) = try makeStore()
        try store.add(content: Data("conteúdo real".utf8), kind: .document, drawer: .textsDocs,
                      name: "doc", createdAt: 1, id: "d")
        try store.setExtractedText("texto derivado do OCR", for: "d")

        let archive = try store.exportArchive(passphrase: "frase-de-teste-长")
        let destBlobs = InMemoryBlobStore()
        let device = SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32)))
        let (_, destSession) = try VaultArchive.restore(archive, passphrase: "frase-de-teste-长",
                                                        into: destBlobs, device: device,
                                                        newPassword: "87654321", kdf: .testFast())
        let dest = try VaultStore(session: destSession, blobs: destBlobs)
        XCTAssertEqual(dest.items().map(\.id), ["d"], "o item viaja")
        XCTAssertEqual(try dest.read(dest.items()[0]), Data("conteúdo real".utf8))
        XCTAssertNil(try dest.extractedText(for: "d"), "o texto extraído NÃO viaja (regenerável no destino)")
        XCTAssertFalse(dest.hasExtractedText(for: "d"))
    }

    // MARK: - Vetor semântico (fase 2b)

    func testEmbedding_roundTrip_emptyValid_unknownThrows() throws {
        let (store, _, _) = try makeStore()
        try store.add(content: Data("nota".utf8), kind: .text, drawer: .textsDocs, name: "n",
                      createdAt: 1, id: "a")
        XCTAssertNil(try store.embedding(for: "a"))
        XCTAssertFalse(store.hasEmbedding(for: "a"))

        let payload = Data([1, 0, 2, 0x3F, 0x80, 0, 0, 0x40, 0, 0, 0])   // opaco p/ o núcleo
        try store.setEmbedding(payload, for: "a")
        XCTAssertEqual(try store.embedding(for: "a"), payload)
        XCTAssertTrue(store.hasEmbedding(for: "a"))

        try store.setEmbedding(Data(), for: "a")   // vazio = processado, nada a embutir
        XCTAssertEqual(try store.embedding(for: "a"), Data())
        XCTAssertTrue(store.hasEmbedding(for: "a"))

        XCTAssertThrowsError(try store.setEmbedding(payload, for: "fantasma"))
    }

    func testEmbedding_shredOnDelete_andPurge_andNotInArchive() throws {
        let (store, session, blobs) = try makeStore()
        try store.add(content: Data("um".utf8), kind: .text, drawer: .textsDocs, name: "n",
                      createdAt: 1, id: "a")
        try store.add(content: Data("dois".utf8), kind: .text, drawer: .textsDocs, name: "t",
                      createdAt: 1000, id: "t", expiresAt: 2000)
        try store.setEmbedding(Data([9, 9]), for: "a")
        try store.setEmbedding(Data([8, 8]), for: "t")
        let keyA = try session.storageKey(VaultStore.embedLabel("a"))
        let keyT = try session.storageKey(VaultStore.embedLabel("t"))

        try store.delete("a")
        XCTAssertNil(try blobs.get(keyA), "vetor morre com o item")
        XCTAssertEqual(try store.purgeExpired(now: 2000), 1)
        XCTAssertNil(try blobs.get(keyT), "TTL leva o vetor junto")

        // Não viaja no arquivo portátil.
        try store.add(content: Data("fica".utf8), kind: .text, drawer: .textsDocs, name: "f",
                      createdAt: 1, id: "f")
        try store.setEmbedding(Data([7]), for: "f")
        let archive = try store.exportArchive(passphrase: "frase-de-teste-长")
        let destBlobs = InMemoryBlobStore()
        let device = SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32)))
        let (_, destSession) = try VaultArchive.restore(archive, passphrase: "frase-de-teste-长",
                                                        into: destBlobs, device: device,
                                                        newPassword: "87654321", kdf: .testFast())
        let dest = try VaultStore(session: destSession, blobs: destBlobs)
        XCTAssertFalse(dest.hasEmbedding(for: "f"), "vetor não viaja (regenerável)")
    }

    // MARK: - Escopos de indexação

    func testScopes_defaultOn_offPersists_onAgain() throws {
        let (store, session, blobs) = try makeStore()
        XCTAssertTrue(store.contentIndexingEnabled(scope: .photos), "default é LIGADO (ausência de marcador)")
        XCTAssertTrue(store.contentIndexingEnabled(scope: .documents))
        XCTAssertTrue(store.contentIndexingEnabled(scope: .audios), "escopo novo nasce no default")

        try store.setContentIndexing(false, scope: .photos)
        XCTAssertFalse(store.contentIndexingEnabled(scope: .photos))
        XCTAssertTrue(store.contentIndexingEnabled(scope: .documents), "escopos independentes")

        // O DESLIGADO sobrevive a uma sessão nova (releitura do disco).
        let reopened = try VaultStore(session: session, blobs: blobs)
        XCTAssertFalse(reopened.contentIndexingEnabled(scope: .photos))

        try reopened.setContentIndexing(true, scope: .photos)
        XCTAssertTrue(reopened.contentIndexingEnabled(scope: .photos))
    }

    /// Cofres distintos (MKs distintas) não enxergam texto extraído nem marcador um do outro —
    /// as `storageKey` são disjuntas por construção.
    func testOtherVault_seesNothing() throws {
        let (storeA, _, blobs) = try makeStore()
        try storeA.add(content: Data([1]), kind: .photo, drawer: .photosVideos, name: "f",
                       createdAt: 1, id: "a")
        try storeA.setExtractedText("só do cofre A", for: "a")
        try storeA.setContentIndexing(false, scope: .documents)

        let vaultB = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 8, count: 32))))
        let (_, sessionB) = try vaultB.create(password: "outra", kdf: .testFast())
        let storeB = try VaultStore(session: sessionB, blobs: blobs)   // MESMO BlobStore
        XCTAssertNil(try storeB.extractedText(for: "a"))
        XCTAssertFalse(storeB.hasExtractedText(for: "a"))
        XCTAssertTrue(storeB.contentIndexingEnabled(scope: .documents), "marcador do A não vaza pro B")
    }
}
