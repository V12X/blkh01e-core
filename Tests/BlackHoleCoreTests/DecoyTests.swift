import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Testes do cofre falso (decoy) deniável: duas chaves-mestras num só envelope, a senha decide
/// qual abre, nada marca real vs falso, e os dois cofres ficam isolados no mesmo BlobStore.
@MainActor
final class DecoyTests: XCTestCase {

    private func newVault() -> Vault {
        Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32))))
    }

    // MARK: Estrutura / indistinguibilidade

    func testEnvelope_hasFixedSlotCount_ofEqualSize() throws {
        let (env, _) = try newVault().create(password: "real", kdf: .testFast())
        XCTAssertEqual(env.slots.count, VaultEnvelope.slotCount)
        // Slot real e slot-lixo têm o MESMO tamanho: a contagem/tamanho não revela se há decoy.
        XCTAssertEqual(Set(env.slots.map(\.count)).count, 1, "todos os slots têm tamanho idêntico")
    }

    func testCreate_realIndexNotFixed() throws {
        // Ao longo de várias criações, o slot real não fica sempre na mesma posição (índice
        // aleatório). Detecta pelo slot que a senha real abre.
        let vault = newVault()
        var indices = Set<Int>()
        for _ in 0..<24 {
            let (env, _) = try vault.create(password: "real", kdf: .testFast())
            let pdk = try KeyDerivation.deriveKey(password: "real", salt: env.salt, params: env.kdf)
            let aad = try aadOf(env)
            for (i, slot) in env.slots.enumerated() {
                if let inner = try? SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32))).unwrap(slot),
                   AEAD.open(inner, key: pdk, aad: aad) != nil { indices.insert(i) }
            }
        }
        XCTAssertEqual(indices, [0, 1], "o slot real aparece em ambas as posições ao longo do tempo")
    }

    // MARK: Duas senhas → dois cofres

    func testDecoy_realAndDecoyOpenIndependentVaults() throws {
        let vault = newVault()
        let (env0, realSession) = try vault.create(password: "senha-real", kdf: .testFast())

        // Semeia o cofre real.
        let blobs = InMemoryBlobStore()
        let realStore = try VaultStore(session: realSession, blobs: blobs)
        try realStore.add(content: Data("dossiê secreto".utf8), kind: .text, drawer: .textsDocs, name: "real", createdAt: 1, id: "r1")

        // Configura o decoy e semeia conteúdo plausível.
        let (env1, decoySession) = try vault.setDecoy(envelope: env0, password: "senha-real", decoyPassword: "senha-falsa")
        let decoyStore = try VaultStore(session: decoySession, blobs: blobs)
        try decoyStore.add(content: Data("lista de compras".utf8), kind: .text, drawer: .textsDocs, name: "falso", createdAt: 2, id: "d1")

        // Abrir com a senha real → só o dossiê. Abrir com a falsa → só a lista.
        let real = try VaultStore(session: try vault.open(envelope: env1, password: "senha-real"), blobs: blobs)
        XCTAssertEqual(real.items().map(\.name), ["real"])
        XCTAssertEqual(try real.read(real.items()[0]), Data("dossiê secreto".utf8))

        let decoy = try VaultStore(session: try vault.open(envelope: env1, password: "senha-falsa"), blobs: blobs)
        XCTAssertEqual(decoy.items().map(\.name), ["falso"])
        XCTAssertEqual(try decoy.read(decoy.items()[0]), Data("lista de compras".utf8))
    }

    func testDecoy_crossVaultIsolation_cannotReadOther() throws {
        let vault = newVault()
        let (env0, realSession) = try vault.create(password: "real", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        let realStore = try VaultStore(session: realSession, blobs: blobs)
        let realItem = try realStore.add(content: Data("segredo".utf8), kind: .text, drawer: .textsDocs, name: "s", createdAt: 1, id: "r")

        let (_, decoySession) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        let decoyStore = try VaultStore(session: decoySession, blobs: blobs)
        // O decoy não enxerga o item do real, e não consegue decifrá-lo nem com a wrappedFileKey dele.
        XCTAssertTrue(decoyStore.items().isEmpty)
        XCTAssertThrowsError(try decoyStore.read(realItem))
    }

    // MARK: Falhas / regras

    func testDecoy_thirdPasswordOpensNeither() throws {
        let vault = newVault()
        let (env0, _) = try vault.create(password: "real", kdf: .testFast())
        let (env1, _) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        XCTAssertThrowsError(try vault.open(envelope: env1, password: "terceira")) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }

    func testDecoy_rejectsDecoyEqualToReal() throws {
        let vault = newVault()
        let (env0, _) = try vault.create(password: "igual", kdf: .testFast())
        XCTAssertThrowsError(try vault.setDecoy(envelope: env0, password: "igual", decoyPassword: "igual")) {
            XCTAssertEqual($0 as? VaultError, .invalidArgument)
        }
    }

    func testDecoy_wrongRealPasswordCannotSetDecoy() throws {
        let vault = newVault()
        let (env0, _) = try vault.create(password: "real", kdf: .testFast())
        XCTAssertThrowsError(try vault.setDecoy(envelope: env0, password: "ERRADA", decoyPassword: "falsa")) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }

    // MARK: Interação com troca de senha

    func testChangeRealPassword_preservesDecoy() throws {
        let vault = newVault()
        let (env0, _) = try vault.create(password: "real", kdf: .testFast())
        let (env1, _) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        // Troca a senha do cofre real; o decoy tem de continuar abrindo com a senha falsa.
        let env2 = try vault.changePassword(envelope: env1, oldPassword: "real", newPassword: "real2", kdf: .testFast())
        XCTAssertNoThrow(try vault.open(envelope: env2, password: "real2"), "nova senha real abre")
        XCTAssertNoThrow(try vault.open(envelope: env2, password: "falsa"), "decoy preservado")
        XCTAssertThrowsError(try vault.open(envelope: env2, password: "real"), "senha real antiga não abre mais")
    }

    // MARK: storageKey (isolamento de blobs)

    func testStorageKey_deterministicPerSession_distinctAcrossVaults() throws {
        let vault = newVault()
        let (_, s1) = try vault.create(password: "a", kdf: .testFast())
        let (_, s2) = try vault.create(password: "b", kdf: .testFast())
        XCTAssertEqual(try s1.storageKey("index"), try s1.storageKey("index"), "determinística")
        XCTAssertNotEqual(try s1.storageKey("index"), try s1.storageKey("ingest"), "rótulos diferentes → chaves diferentes")
        XCTAssertNotEqual(try s1.storageKey("index"), try s2.storageKey("index"), "cofres diferentes → chaves disjuntas")
        // Sem "/", "+", "=" — seguro como nome de arquivo.
        let k = try s1.storageKey("content/abc")
        XCTAssertFalse(k.contains("/") || k.contains("+") || k.contains("="))
    }

    // Recalcula o AAD canônico do envelope (o mesmo domain-sep do núcleo) para os testes de posição.
    private func aadOf(_ env: VaultEnvelope) throws -> Data {
        var d = Data("BLKH01E/vault-v1".utf8)
        func putU32(_ v: UInt32) { withUnsafeBytes(of: v.bigEndian) { d.append(contentsOf: $0) } }
        func putU64(_ v: UInt64) { withUnsafeBytes(of: v.bigEndian) { d.append(contentsOf: $0) } }
        putU32(UInt32(truncatingIfNeeded: env.version))
        putU64(UInt64(bitPattern: Int64(env.kdf.opsLimit)))
        putU64(UInt64(bitPattern: Int64(env.kdf.memLimit)))
        putU32(UInt32(truncatingIfNeeded: env.kdf.algorithm))
        putU32(UInt32(env.salt.count))
        d.append(contentsOf: env.salt)
        return d
    }
}
