import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Autodestruição por prazo (burn Nível A): purge crypto-shreda no vencimento, retrocompatível com
/// índices antigos, e o prazo VIAJA no arquivo portátil.
@MainActor
final class TTLTests: XCTestCase {

    private func makeStore() throws -> (VaultStore, VaultSession, InMemoryBlobStore) {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 7, count: 32))))
        let (_, session) = try vault.create(password: "s3nha", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        let store = try VaultStore(session: session, blobs: blobs)
        return (store, session, blobs)
    }

    // MARK: - Purge

    func testPurge_beforeDeadline_keepsItem() throws {
        let (store, _, _) = try makeStore()
        try store.add(content: Data("x".utf8), kind: .text, drawer: .textsDocs, name: "n",
                      createdAt: 1000, id: "a", expiresAt: 2000)
        XCTAssertEqual(try store.purgeExpired(now: 1999), 0)
        XCTAssertEqual(store.items().map(\.id), ["a"])
    }

    func testPurge_atAndAfterDeadline_cryptoShreds() throws {
        let (store, session, blobs) = try makeStore()
        let item = try store.add(content: Data("segredo".utf8), kind: .text, drawer: .textsDocs,
                                 name: "n", createdAt: 1000, id: "a", expiresAt: 2000)
        let ckey = try session.storageKey("content/a")
        XCTAssertNotNil(try blobs.get(ckey))

        XCTAssertEqual(try store.purgeExpired(now: 2000), 1, "prazo INCLUSIVO: vence exatamente em expiresAt")
        XCTAssertTrue(store.items().isEmpty, "some do índice")
        XCTAssertNil(try blobs.get(ckey), "ciphertext apagado")
        XCTAssertThrowsError(try store.read(item), "sem a wrappedFileKey, irrecuperável")
    }

    func testPurge_mixed_onlyExpiredDie_singlePersist() throws {
        let (store, _, _) = try makeStore()
        try store.add(content: Data("1".utf8), kind: .text, drawer: .textsDocs, name: "vence", createdAt: 1, id: "v1", expiresAt: 100)
        try store.add(content: Data("2".utf8), kind: .text, drawer: .textsDocs, name: "vence2", createdAt: 1, id: "v2", expiresAt: 150)
        try store.add(content: Data("3".utf8), kind: .text, drawer: .links, name: "fica", createdAt: 1, id: "f1", expiresAt: 900)
        try store.add(content: Data("4".utf8), kind: .text, drawer: .textsDocs, name: "eterno", createdAt: 1, id: "e1")

        XCTAssertEqual(try store.purgeExpired(now: 200), 2)
        XCTAssertEqual(Set(store.items().map(\.id)), ["f1", "e1"])
        XCTAssertEqual(try store.purgeExpired(now: 200), 0, "idempotente")
    }

    /// O purge persiste: uma sessão NOVA (releitura do índice do disco) não ressuscita o item.
    func testPurge_survivesReload() throws {
        let (store, session, blobs) = try makeStore()
        try store.add(content: Data("x".utf8), kind: .text, drawer: .textsDocs, name: "n",
                      createdAt: 1, id: "a", expiresAt: 10)
        try store.purgeExpired(now: 11)
        let reopened = try VaultStore(session: session, blobs: blobs)
        XCTAssertTrue(reopened.items().isEmpty)
    }

    // MARK: - Validação

    func testAdd_expiryNotAfterCreation_rejected() throws {
        let (store, _, _) = try makeStore()
        XCTAssertThrowsError(try store.add(content: Data("x".utf8), kind: .text, drawer: .textsDocs,
                                           name: "n", createdAt: 1000, id: "a", expiresAt: 1000)) {
            XCTAssertEqual($0 as? VaultError, .invalidArgument)
        }
        XCTAssertThrowsError(try store.add(content: Data("x".utf8), kind: .text, drawer: .textsDocs,
                                           name: "n", createdAt: 1000, id: "b", expiresAt: .infinity)) {
            XCTAssertEqual($0 as? VaultError, .invalidArgument)
        }
    }

    // MARK: - Retrocompatibilidade

    /// Índice gravado ANTES do campo existir (JSON sem `expiresAt`) decodifica com `nil` — sem
    /// migração, sem brick.
    func testDecode_legacyItemWithoutExpiresAt_isNil() throws {
        let legacy = #"{"id":"a","drawer":"textsDocs","kind":"text","name":"n","size":1,"createdAt":1,"wrappedFileKey":"QUJD"}"#
        let item = try JSONDecoder().decode(VaultItem.self, from: Data(legacy.utf8))
        XCTAssertNil(item.expiresAt)
    }

    /// Item SEM prazo não ganha o campo no JSON (o encoder omite nil) — o shape do índice novo é
    /// idêntico ao antigo para quem não usa TTL.
    func testEncode_noExpiry_omitsField() throws {
        let item = VaultItem(id: "a", drawer: .textsDocs, kind: .text, name: "n", size: 1,
                             createdAt: 1, wrappedFileKey: Data([1]))
        let json = String(data: try JSONEncoder().encode(item), encoding: .utf8)!
        XCTAssertFalse(json.contains("expiresAt"))
    }

    // MARK: - Arquivo portátil

    /// O prazo VIAJA no arquivo: migrar de aparelho não vira brecha para item vencido reviver
    /// eternamente — no destino, o purge da próxima abertura o destrói.
    func testExpiry_survivesArchiveRoundTrip() throws {
        let (store, session, blobs) = try makeStore()
        try store.add(content: Data("temporário".utf8), kind: .text, drawer: .textsDocs,
                      name: "t", createdAt: 1000, id: "a", expiresAt: 5000)
        let archive = try VaultArchive.export(session: session, items: store.items(),
                                              blobs: blobs, passphrase: "f", params: .testFast())

        let blobsB = InMemoryBlobStore()
        let deviceB = SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 0xB2, count: 32)))
        let (_, sessionB) = try VaultArchive.restore(archive, passphrase: "f", into: blobsB,
                                                     device: deviceB, newPassword: "nova", kdf: .testFast())
        let storeB = try VaultStore(session: sessionB, blobs: blobsB)
        XCTAssertEqual(storeB.items().first?.expiresAt, 5000, "prazo preservado na migração")
        XCTAssertEqual(try storeB.purgeExpired(now: 5001), 1, "e é aplicável no destino")
    }
}
