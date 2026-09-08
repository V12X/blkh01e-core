import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Subpastas (UM nível por gaveta): criar/renomear/apagar, mover itens, derivar pastas dos itens,
/// persistência real (recarrega o store do mesmo BlobStore) e retrocompatibilidade do campo `folder`.
@MainActor
final class VaultFolderTests: XCTestCase {

    private func makeStore() throws -> (VaultSession, InMemoryBlobStore, VaultStore) {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32))))
        let (_, session) = try vault.create(password: "s3nha", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        return (session, blobs, try VaultStore(session: session, blobs: blobs))
    }

    @discardableResult
    private func add(_ store: VaultStore, _ id: String, _ drawer: VaultDrawer, folder: String? = nil) throws -> VaultItem {
        try store.add(content: Data(id.utf8), kind: .text, drawer: drawer, name: id, createdAt: 1, id: id, folder: folder)
    }

    // MARK: - Criar / listar / raiz

    func testCreateEmptyFolder_showsUp() throws {
        let (_, _, store) = try makeStore()
        try store.createFolder("Trabalho", in: .textsDocs)
        XCTAssertEqual(store.folders(in: .textsDocs), ["Trabalho"])
        XCTAssertTrue(store.items(in: .textsDocs, folder: "Trabalho").isEmpty)   // vazia
    }

    func testRootVsFolder_filtering() throws {
        let (_, _, store) = try makeStore()
        try add(store, "solto", .textsDocs)                      // raiz
        try add(store, "dentro", .textsDocs, folder: "Trabalho") // subpasta
        XCTAssertEqual(store.items(in: .textsDocs, folder: nil).map(\.id), ["solto"])
        XCTAssertEqual(store.items(in: .textsDocs, folder: "Trabalho").map(\.id), ["dentro"])
        XCTAssertEqual(store.items(in: .textsDocs).count, 2)     // a listagem geral traz os dois
    }

    func testFoldersDerivedFromItems() throws {
        // Sem createFolder: a pasta aparece só por causa do item nela (cobre import de arquivo).
        let (_, _, store) = try makeStore()
        try add(store, "x", .textsDocs, folder: "Recibos")
        XCTAssertEqual(store.folders(in: .textsDocs), ["Recibos"])
    }

    func testDuplicateFolder_rejected() throws {
        let (_, _, store) = try makeStore()
        try store.createFolder("Trabalho", in: .textsDocs)
        XCTAssertThrowsError(try store.createFolder("trabalho", in: .textsDocs))   // case-insensitive
        XCTAssertThrowsError(try store.createFolder("  ", in: .textsDocs))          // vazio
    }

    // MARK: - Mover / renomear / apagar

    func testMoveItemBetweenFolders() throws {
        let (_, _, store) = try makeStore()
        try add(store, "a", .textsDocs)
        try store.move("a", toFolder: "Trabalho")
        XCTAssertEqual(store.items(in: .textsDocs, folder: "Trabalho").map(\.id), ["a"])
        try store.move("a", toFolder: nil)   // de volta à raiz
        XCTAssertEqual(store.items(in: .textsDocs, folder: nil).map(\.id), ["a"])
    }

    func testRenameFolder_movesItemsAndRegistry() throws {
        let (_, _, store) = try makeStore()
        try store.createFolder("Trabalho", in: .textsDocs)
        try add(store, "a", .textsDocs, folder: "Trabalho")
        try store.renameFolder("Trabalho", to: "Serviço", in: .textsDocs)
        XCTAssertEqual(store.folders(in: .textsDocs), ["Serviço"])
        XCTAssertEqual(store.items(in: .textsDocs, folder: "Serviço").map(\.id), ["a"])
        XCTAssertTrue(store.items(in: .textsDocs, folder: "Trabalho").isEmpty)
    }

    func testDeleteFolder_returnsItemsToRoot() throws {
        let (_, _, store) = try makeStore()
        try store.createFolder("Trabalho", in: .textsDocs)
        try add(store, "a", .textsDocs, folder: "Trabalho")
        try store.deleteFolder("Trabalho", in: .textsDocs)
        XCTAssertEqual(store.folders(in: .textsDocs), [])                     // registro limpo
        XCTAssertEqual(store.items(in: .textsDocs, folder: nil).map(\.id), ["a"])  // item de volta à raiz (não apagado)
    }

    func testMoveBetweenDrawers_clearsFolder() throws {
        let (_, _, store) = try makeStore()
        try add(store, "a", .textsDocs, folder: "Trabalho")
        try store.move("a", to: .links)   // troca de gaveta → subpasta some (é da gaveta antiga)
        XCTAssertNil(store.items(in: .links).first?.folder)
    }

    // MARK: - Persistência e retrocompat

    func testPersistence_reloadKeepsFoldersAndAssignments() throws {
        let (session, blobs, store) = try makeStore()
        try store.createFolder("Vazia", in: .textsDocs)
        try add(store, "a", .textsDocs, folder: "Trabalho")
        // Recarrega do MESMO BlobStore (nova instância) — tudo tem de voltar.
        let store2 = try VaultStore(session: session, blobs: blobs)
        XCTAssertEqual(store2.folders(in: .textsDocs), ["Trabalho", "Vazia"])
        XCTAssertEqual(store2.items(in: .textsDocs, folder: "Trabalho").map(\.id), ["a"])
    }

    func testLiveDefault_persistsUnderMK() throws {
        let (session, blobs, store) = try makeStore()
        XCTAssertFalse(try store.liveDefault())            // off por padrão
        try store.setLiveDefault(true)
        XCTAssertTrue(try store.liveDefault())
        let store2 = try VaultStore(session: session, blobs: blobs)   // recarrega
        XCTAssertTrue(try store2.liveDefault())
        try store2.setLiveDefault(false)
        XCTAssertFalse(try store2.liveDefault())
    }

    func testNearbyDefault_persistsUnderMK_eIndependenteDoLive() throws {
        let (session, blobs, store) = try makeStore()
        XCTAssertFalse(try store.nearbyDefault())          // off por padrão
        try store.setNearbyDefault(true)
        XCTAssertTrue(try store.nearbyDefault())
        // As duas preferências são INDEPENDENTES: ligar uma não pode ligar a outra (elas viraram
        // ajustes globais de entrega, e confundir as chaves ativaria rádio sem o usuário pedir).
        XCTAssertFalse(try store.liveDefault())
        try store.setLiveDefault(true)
        XCTAssertTrue(try store.nearbyDefault())
        let store2 = try VaultStore(session: session, blobs: blobs)   // recarrega
        XCTAssertTrue(try store2.nearbyDefault())
        try store2.setNearbyDefault(false)
        XCTAssertFalse(try store2.nearbyDefault())
        XCTAssertTrue(try store2.liveDefault())            // desligar uma não desliga a outra
    }

    func testBackCompat_oldItemDecodesWithNilFolder() throws {
        // Item sem o campo `folder` (índice antigo) → decodifica como raiz (folder nil).
        let old = #"[{"id":"x","drawer":"textsDocs","kind":"text","name":"n","size":1,"createdAt":1,"wrappedFileKey":""}]"#
        let items = try JSONDecoder().decode([VaultItem].self, from: Data(old.utf8))
        XCTAssertEqual(items.count, 1)
        XCTAssertNil(items[0].folder)
    }
}
