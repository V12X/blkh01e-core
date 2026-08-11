import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Vetores CONGELADOS: fixtures geradas uma única vez e gravadas como literais. Round-trips
/// simétricos (encrypt→decrypt na mesma versão do código) NÃO detectam quebra de formato — estes
/// testes sim. Se um deles falhar, o formato de fio v1 / o JSON do envelope v2 mudou: isso brica
/// mensagens já enviadas / cofres já em disco. NUNCA "conserte" regenerando a fixture — a mudança
/// exige bump de versão com caminho de migração.
@MainActor
final class FrozenVectorTests: XCTestCase {

    // Gerado com params .testFast() (dentro da faixa sã e ≤ .standard(), então decodável pela
    // API pública), senha "senha-fixa-v1".
    private let frozenArmoredV1 = "BLKH01E.1.QkgwMQEBAAAAAgQAAABy4XdN9qZu_ta-osFRM_U38HIhdsCi_v4BhkX_9-hQ-K-84h6NypYDUHcKRpoPEOtUeCVYmKsksuyBXdDklFg0b_iUSYwxFgUEymXeA28-3KVN3Y9bjTStDUiB63XynTxil-mOta27kE95G_u59fqkXCsN4LiUos7nec20KpdPRzsH1HdetkAoES3TTj3PgtQ1SzI0wuK8aHpwn0mg8WeFN-XMk3oEAvVfkKRdJwDTCUv1ZxGo26fsKh1PV-0KFtuF8gDXLk_zBHbKrZ4fmd_Frw-5W-LTkxhEBXfMiJ6uQwc_Lxx8R4YV2tpgMgNN_eRGaO-vhj-Dl8wnCgf-Pw7gs0oymlFy02_e0S5NSF7TdVHfGv5uIdRfOT3ItesU7o0MsuFLIZyobuvcpuQ"

    // Envelope v2 gerado com SoftwareDeviceKeystore(key: 0x07×32), senha "senha-envelope-v2",
    // params .testFast().
    private let frozenEnvelopeV2JSON = #"{"kdf":{"opsLimit":2,"memLimit":67108864,"algorithm":1},"salt":[117,220,221,30,3,62,178,100,48,74,18,200,96,67,54,99],"slots":["3kIk+iwfJnntHUalqQPi0Jz+9OhF7jqkyIHzLslPccVIOqBC+ar8QxgWWs096HycvV\/xcqdxCPub91OBoH5EG1JZoOSAOWucdHuQBBBW2b7H0AXK\/Gp5xg==","E7IvwTGEALR\/ESxk4nl3Bvd2SW0bAgbt5wvwTW+wfLddeNfreMNLev6Vmaaj1x54exnqM5Jujpz5dHf9wThCnMO8aEw+Gdkyb0fAvNcoGGrMTTbaSSTqxQ=="],"version":2}"#

    func testDecrypt_frozenV1Vector_stillDecrypts() throws {
        let plaintext = try SecureMessage.decrypt(frozenArmoredV1, password: "senha-fixa-v1")
        XCTAssertEqual(plaintext, Data("mensagem congelada v1 🕳️".utf8))
    }

    func testDecrypt_frozenV1Vector_wrongPasswordStillUnified() {
        XCTAssertThrowsError(try SecureMessage.decrypt(frozenArmoredV1, password: "outra")) {
            XCTAssertEqual($0 as? MessageError, .wrongPasswordOrCorrupt)
        }
    }

    func testOpen_frozenV2EnvelopeJSONFixture_opensWithKnownPassword() throws {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 7, count: 32))))
        let session = try vault.open(fromEnvelopeData: Data(frozenEnvelopeV2JSON.utf8),
                                     password: "senha-envelope-v2")
        XCTAssertTrue(session.isOpen)
        // A sessão recuperada produz chaves de armazenamento estáveis (deriva da MESMA MK).
        XCTAssertFalse(try session.storageKey("index").isEmpty)
    }

    func testOpen_frozenV2EnvelopeJSONFixture_wrongPasswordUnified() {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 7, count: 32))))
        XCTAssertThrowsError(try vault.open(fromEnvelopeData: Data(frozenEnvelopeV2JSON.utf8),
                                            password: "errada")) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }
}

/// Ciclo de vida do decoy nas PONTAS (o meio — create/setDecoy/changePassword do real — já era
/// coberto em DecoyTests).
@MainActor
final class DecoyLifecycleTests: XCTestCase {

    private func newVault() -> Vault {
        Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 9, count: 32))))
    }

    /// `recover()` promete descartar o decoy (doc do núcleo) — congela essa semântica.
    func testRecover_discardsDecoy_realDataSurvives() throws {
        let vault = newVault()
        let blobs = InMemoryBlobStore()
        let (env0, realSession) = try vault.create(password: "real", kdf: .testFast())
        let realStore = try VaultStore(session: realSession, blobs: blobs)
        try realStore.add(content: Data("segredo".utf8), kind: .text, drawer: .textsDocs, name: "s", createdAt: 1, id: "r1")

        let (env1, decoySession) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        let decoyStore = try VaultStore(session: decoySession, blobs: blobs)
        try decoyStore.add(content: Data("compras".utf8), kind: .text, drawer: .textsDocs, name: "d", createdAt: 2, id: "d1")

        let recEnv = try vault.addRecovery(envelope: env1, password: "real", recoveryPhrase: "frase de teste", kdf: .testFast())
        let (newMain, session) = try vault.recover(recoveryEnvelope: recEnv, phrase: "frase de teste",
                                                   newPassword: "nova-senha", kdf: .testFast())

        // Mesma MK → os dados reais continuam legíveis.
        let store = try VaultStore(session: session, blobs: blobs)
        XCTAssertEqual(store.items().map(\.name), ["s"])
        XCTAssertEqual(try store.read(store.items()[0]), Data("segredo".utf8))

        // Novo envelope: senha nova abre; a antiga e a do DECOY não (decoy descartado).
        XCTAssertNoThrow(try vault.open(envelope: newMain, password: "nova-senha"))
        XCTAssertThrowsError(try vault.open(envelope: newMain, password: "real"))
        XCTAssertThrowsError(try vault.open(envelope: newMain, password: "falsa")) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }

    /// Troca de senha PELO LADO DO DECOY: o cofre real não pode ser tocado.
    func testChangeDecoyPassword_preservesRealVault() throws {
        let vault = newVault()
        let (env0, _) = try vault.create(password: "real", kdf: .testFast())
        let (env1, _) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        let env2 = try vault.changePassword(envelope: env1, oldPassword: "falsa", newPassword: "falsa2", kdf: .testFast())
        XCTAssertNoThrow(try vault.open(envelope: env2, password: "falsa2"), "nova senha do decoy abre")
        XCTAssertNoThrow(try vault.open(envelope: env2, password: "real"), "cofre real intacto")
        XCTAssertThrowsError(try vault.open(envelope: env2, password: "falsa"), "senha antiga do decoy não abre")
    }

    /// `setDecoy` de novo re-atribui: a senha falsa ANTIGA morre, a nova vale, o real fica.
    func testSetDecoy_reassign_oldDecoyPasswordStopsOpening() throws {
        let vault = newVault()
        let (env0, _) = try vault.create(password: "real", kdf: .testFast())
        let (env1, _) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa1")
        let (env2, _) = try vault.setDecoy(envelope: env1, password: "real", decoyPassword: "falsa2")
        XCTAssertNoThrow(try vault.open(envelope: env2, password: "real"))
        XCTAssertNoThrow(try vault.open(envelope: env2, password: "falsa2"))
        XCTAssertThrowsError(try vault.open(envelope: env2, password: "falsa1")) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault)
        }
    }

    /// Indistinguibilidade APÓS setDecoy: mesmo nº de slots, todos do mesmo tamanho do create
    /// (envelope com decoy não pode ter shape diferente de um sem).
    func testSetDecoy_envelopeShape_identicalToFreshCreate() throws {
        let vault = newVault()
        let (env0, _) = try vault.create(password: "real", kdf: .testFast())
        let freshSizes = env0.slots.map(\.count)
        let (env1, _) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        XCTAssertEqual(env1.slots.count, VaultEnvelope.slotCount)
        XCTAssertEqual(env1.slots.map(\.count), freshSizes, "tamanhos de slot idênticos ao create")
        XCTAssertEqual(env1.salt, env0.salt, "salt/KDF compartilhados não giram no setDecoy")
    }
}
