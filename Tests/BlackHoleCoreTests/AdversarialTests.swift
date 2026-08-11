import XCTest
import CryptoKit
@testable import BlackHoleCore

// MARK: - L6: corrupção ESTRUTURAL do envelope
//
// Os testes existentes adulteram VALORES (bit-flip em salt/version/kdf). Estes atacam a FORMA:
// caem no `guard` de `unlockMasterKey` (ramo com `decoyWork`), que era um caminho sem cobertura.
@MainActor
final class EnvelopeStructureTests: XCTestCase {

    private let deviceKey = SymmetricKey(data: Data(repeating: 9, count: 32))
    private func newVault() -> Vault { Vault(device: SoftwareDeviceKeystore(key: deviceKey)) }

    private func expectUnified(_ vault: Vault, _ env: VaultEnvelope, _ pw: String,
                               _ msg: String, line: UInt = #line) {
        XCTAssertThrowsError(try vault.open(envelope: env, password: pw), msg, line: line) {
            XCTAssertEqual($0 as? VaultError, .wrongPasswordOrNoVault, msg, line: line)
        }
    }

    func testOpen_slotCountNotTwo_unified() throws {
        let vault = newVault()
        let (env, _) = try vault.create(password: "real", kdf: .testFast())

        var tooFew = env; tooFew.slots = [env.slots[0]]
        expectUnified(vault, tooFew, "real", "1 slot: forma inválida")

        var tooMany = env; tooMany.slots = env.slots + [env.slots[0]]
        expectUnified(vault, tooMany, "real", "3 slots: forma inválida")

        var none = env; none.slots = []
        expectUnified(vault, none, "real", "0 slots: forma inválida")
    }

    func testOpen_versionBelowMinimum_unified() throws {
        let vault = newVault()
        let (env, _) = try vault.create(password: "real", kdf: .testFast())
        var old = env; old.version = Vault.minSupportedVersion - 1
        expectUnified(vault, old, "real", "versão abaixo do mínimo não abre")
    }

    func testOpen_saltWrongLength_unified() throws {
        let vault = newVault()
        let (env, _) = try vault.create(password: "real", kdf: .testFast())
        var short = env; short.salt = Array(env.salt.prefix(3))
        expectUnified(vault, short, "real", "salt truncado não abre")
    }

    /// Slot de OUTRO envelope, com a MESMA senha: o AAD canônico (version|kdf|salt) difere, então
    /// o slot transplantado não abre. Fecha o "corta-e-cola" de slots entre cofres.
    func testOpen_slotTransplantedFromOtherEnvelope_unified() throws {
        let vault = newVault()
        let (envA, _) = try vault.create(password: "mesma-senha", kdf: .testFast())
        let (envB, _) = try vault.create(password: "mesma-senha", kdf: .testFast())
        var frankenstein = envA
        frankenstein.slots = envB.slots   // salt/AAD continuam os de A
        expectUnified(vault, frankenstein, "mesma-senha", "slot de outro envelope não abre")
    }

    /// INVARIANTE POSITIVA: a ordem dos slots não importa (`unlockMasterKey` tenta todos). É o que
    /// permite o índice real ser aleatório — se isto quebrar, a deniabilidade quebra junto.
    func testOpen_slotsReordered_stillOpens() throws {
        let vault = newVault()
        let (env, _) = try vault.create(password: "real", kdf: .testFast())
        var flipped = env; flipped.slots.reverse()
        XCTAssertNoThrow(try vault.open(envelope: flipped, password: "real"))
    }

    func testOpen_slotsReordered_decoyStillOpensToo() throws {
        let vault = newVault()
        let (env0, _) = try vault.create(password: "real", kdf: .testFast())
        let (env1, _) = try vault.setDecoy(envelope: env0, password: "real", decoyPassword: "falsa")
        var flipped = env1; flipped.slots.reverse()
        XCTAssertNoThrow(try vault.open(envelope: flipped, password: "real"))
        XCTAssertNoThrow(try vault.open(envelope: flipped, password: "falsa"))
    }
}

// MARK: - L7: contrato de carga do índice (ausente vs. ilegível)
@MainActor
final class IndexCorruptionTests: XCTestCase {

    private func makeSession() throws -> (VaultSession, InMemoryBlobStore) {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 7, count: 32))))
        let (_, session) = try vault.create(password: "s3nha", kdf: .testFast())
        return (session, InMemoryBlobStore())
    }

    /// Blob AUSENTE = cofre novo → abre vazio (não é erro).
    func testInit_noIndexBlob_opensEmpty() throws {
        let (session, blobs) = try makeSession()
        let store = try VaultStore(session: session, blobs: blobs)
        XCTAssertTrue(store.items().isEmpty)
    }

    /// Blob PRESENTE e truncado → `.corrupted`. Abrir vazio mascararia perda de dados e o próximo
    /// `add` sobrescreveria o índice, orfanando todos os blobs (correção de contrato).
    func testInit_truncatedIndexBlob_throwsCorrupted() throws {
        let (session, blobs) = try makeSession()
        try blobs.put(try session.storageKey("index"), Data([0x00, 0x01]))   // < 4 bytes
        XCTAssertThrowsError(try VaultStore(session: session, blobs: blobs)) {
            XCTAssertEqual($0 as? VaultError, .corrupted)
        }
    }

    /// `len` forjado maior que o blob → unpack falha → `.corrupted` (nunca leitura fora dos limites).
    func testInit_forgedIndexLength_throwsCorrupted() throws {
        let (session, blobs) = try makeSession()
        var forged = Data()
        withUnsafeBytes(of: UInt32(0xFFFF_FFF0).bigEndian) { forged.append(contentsOf: $0) }
        forged.append(Data(repeating: 0xAB, count: 32))
        try blobs.put(try session.storageKey("index"), forged)
        XCTAssertThrowsError(try VaultStore(session: session, blobs: blobs)) {
            XCTAssertEqual($0 as? VaultError, .corrupted)
        }
    }

    /// Estrutura válida, ciphertext adulterado → AEAD falha → `.corrupted`.
    func testInit_tamperedIndexCiphertext_throwsCorrupted() throws {
        let (session, blobs) = try makeSession()
        let store = try VaultStore(session: session, blobs: blobs)
        try store.add(content: Data("x".utf8), kind: .text, drawer: .textsDocs, name: "n", createdAt: 1, id: "i1")

        let key = try session.storageKey("index")
        var blob = try XCTUnwrap(try blobs.get(key))
        blob[blob.count - 1] ^= 0xFF          // flip no último byte (tag do AEAD)
        try blobs.put(key, blob)

        XCTAssertThrowsError(try VaultStore(session: session, blobs: blobs)) {
            XCTAssertEqual($0 as? VaultError, .corrupted)
        }
    }

    /// Índice íntegro sobrevive a uma sessão nova (não-regressão do caminho feliz).
    func testInit_validIndex_reloads() throws {
        let (session, blobs) = try makeSession()
        let store = try VaultStore(session: session, blobs: blobs)
        try store.add(content: Data("dado".utf8), kind: .text, drawer: .textsDocs, name: "nome", createdAt: 5, id: "i9")
        let reopened = try VaultStore(session: session, blobs: blobs)
        XCTAssertEqual(reopened.items().map(\.id), ["i9"])
    }
}

// MARK: - L8: SecureMessage adversarial (magic / mode / bit-flip no header)
//
// O único tamper testado até aqui (`testTamper_fails`) flipa o ÚLTIMO caractere — cai no
// ciphertext. Estes atacam o HEADER, que é quem faz o roteamento das 3 falhas distintas.
final class SecureMessageAdversarialTests: XCTestCase {

    private func armoredFixture() throws -> String {
        try SecureMessage.encrypt(Data("mensagem".utf8), password: "senha", params: .testFast())
    }

    /// Reconstrói o token com o payload adulterado (mantendo o rótulo externo de versão).
    private func rebuilt(_ armored: String, _ mutate: (inout Data) -> Void) throws -> String {
        let parts = armored.split(separator: ".")
        var payload = try XCTUnwrap(Self.b64urlDecode(String(parts[2])))
        mutate(&payload)
        return "BLKH01E.\(parts[1]).\(Self.b64urlEncode(payload))"
    }

    func testDecrypt_badMagic_malformed() throws {
        let bad = try rebuilt(try armoredFixture()) { $0[0] = 0x58 }   // "BH01" → "XH01"
        XCTAssertThrowsError(try SecureMessage.decrypt(bad, password: "senha")) {
            XCTAssertEqual($0 as? MessageError, .malformed)
        }
    }

    /// Modo desconhecido (versão válida) → `.unsupportedVersion`, NÃO `.malformed`: é o degrau
    /// que permite `mode` 2/3 (X25519/PQ) no futuro sem quebrar v1.
    func testDecrypt_unknownMode_unsupportedVersion() throws {
        let bad = try rebuilt(try armoredFixture()) { $0[5] = 2 }
        XCTAssertThrowsError(try SecureMessage.decrypt(bad, password: "senha")) {
            XCTAssertEqual($0 as? MessageError, .unsupportedVersion)
        }
    }

    /// Bit-flip no SALT dentro do header: params seguem sãos, mas a chave derivada e o AAD mudam →
    /// falha de autenticação, não "malformed". Prova que o header inteiro é AAD.
    func testDecrypt_headerSaltBitFlip_wrongPasswordOrCorrupt() throws {
        let bad = try rebuilt(try armoredFixture()) { $0[14] ^= 0x01 }
        XCTAssertThrowsError(try SecureMessage.decrypt(bad, password: "senha")) {
            XCTAssertEqual($0 as? MessageError, .wrongPasswordOrCorrupt)
        }
    }

    /// Bit-flip no byte de MODO já é coberto acima; aqui o flip no opsLimit (params ainda sãos,
    /// mas ≠ dos usados na selagem) → AAD divergente → falha de autenticação.
    func testDecrypt_headerOpsLimitTampered_failsClosed() throws {
        let armored = try armoredFixture()
        let bad = try rebuilt(armored) { $0[9] = $0[9] &+ 1 }
        XCTAssertThrowsError(try SecureMessage.decrypt(bad, password: "senha"))
    }

    func testDecrypt_invalidBase64Length_malformed() throws {
        // 5 chars do alfabeto base64url ≡ 1 (mod 4): comprimento impossível → decode falha.
        XCTAssertThrowsError(try SecureMessage.decrypt("BLKH01E.1.AAAAA", password: "senha")) {
            XCTAssertEqual($0 as? MessageError, .malformed)
        }
    }

    // base64url próprio (os helpers do núcleo são `private`).
    private static func b64urlEncode(_ d: Data) -> String {
        d.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    private static func b64urlDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        return Data(base64Encoded: b)
    }
}
