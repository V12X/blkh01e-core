import Foundation
import CryptoKit

/// Envelope persistido no disco. NÃO contém a senha nem a chave-mestra em claro: só versão,
/// parâmetros do KDF (A1), salt e um conjunto de SLOTS — cada slot é uma chave-mestra embrulhada
/// em dois fatores (dispositivo ∘ senha), sob o MESMO salt/KDF. A senha digitada abre o slot que
/// combina; os demais permanecem indistinguíveis de aleatório. Deniabilidade: nada no envelope
/// marca qual slot é "real" e qual é "falso"/lixo — só a senha decide. Destruir este blob =
/// crypto-shred de TODOS os cofres (irrecuperável).
public struct VaultEnvelope: Codable, Equatable {
    /// Nº fixo de slots. Todo envelope tem exatamente este número, sempre — a mera contagem não
    /// revela se um cofre falso foi configurado.
    public static let slotCount = 2

    public var version: Int
    public var kdf: KDFParams
    public var salt: [UInt8]
    public var slots: [Data]

    public init(version: Int, kdf: KDFParams, salt: [UInt8], slots: [Data]) {
        self.version = version
        self.kdf = kdf
        self.salt = salt
        self.slots = slots
    }
}

/// Cria e abre cofres. Parametrizado pelo `DeviceKeystore` (Secure Enclave no aparelho,
/// software nos testes). Cofres diferentes (real e falso) são envelopes independentes.
public struct Vault {
    public static let minSupportedVersion = 2
    public static let currentVersion = 2
    /// Faixa de versões abríveis. Evita bricar a base num bump futuro (correção de regressão).
    public static var supportedVersions: ClosedRange<Int> { minSupportedVersion...currentVersion }

    public let device: DeviceKeystore
    public init(device: DeviceKeystore) { self.device = device }

    // MARK: - AAD canônico (autentica version+kdf+salt com a MK embrulhada) — B1
    private func aad(for env: VaultEnvelope) -> Data {
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

    /// Embrulha UMA chave-mestra num slot: AEAD sob a PDK (fator senha) e depois DeviceKeystore
    /// (fator dispositivo), com o `aad` canônico do envelope. `aad` cobre version/kdf/salt —
    /// compartilhados por todos os slots.
    private func sealSlot(masterKey mk: SymmetricKey, pdk: SymmetricKey, aad: Data) throws -> Data {
        var mkData = mk.withUnsafeBytes { Data($0) }
        defer { mkData.resetBytes(in: 0..<mkData.count) }
        let inner = try AEAD.seal(mkData, key: pdk, aad: aad)
        return try device.wrap(inner)
    }

    /// Slot-lixo indistinguível: uma MK aleatória embrulhada sob uma CHAVE aleatória (não derivada
    /// de senha). Estruturalmente idêntico a um slot real; nenhuma senha do usuário o abre. Preenche
    /// o slot não usado para que a existência (ou não) de um cofre falso não seja observável.
    private func junkSlot(aad: Data) throws -> Data {
        let mk = SymmetricKey(size: .bits256)
        let key = SymmetricKey(size: .bits256)   // chave aleatória: nenhuma PDK jamais coincide
        return try sealSlot(masterKey: mk, pdk: key, aad: aad)
    }

    /// Monta um envelope novo com o cofre `password` num slot de índice ALEATÓRIO e um slot-lixo
    /// no outro. Índice aleatório = a posição não vaza qual slot é o real (deniabilidade).
    /// `internal` (não privado) porque `VaultArchive.restore` adota uma MK vinda de um arquivo e
    /// precisa criar o envelope principal DESTE aparelho para ela.
    func makeEnvelope(masterKey mk: SymmetricKey, password: String, kdf: KDFParams) throws -> VaultEnvelope {
        let salt = try KeyDerivation.newSalt()
        let shell = VaultEnvelope(version: Vault.currentVersion, kdf: kdf, salt: salt, slots: [])
        let aadData = aad(for: shell)
        let pdk = try KeyDerivation.deriveKey(password: password, salt: salt, params: kdf)
        let realSlot = try sealSlot(masterKey: mk, pdk: pdk, aad: aadData)

        var rng = SystemRandomNumberGenerator()
        let realIdx = Int.random(in: 0..<VaultEnvelope.slotCount, using: &rng)
        var slots: [Data] = []
        for i in 0..<VaultEnvelope.slotCount {
            slots.append(i == realIdx ? realSlot : try junkSlot(aad: aadData))
        }
        var env = shell
        env.slots = slots
        return env
    }

    // MARK: - Criar (força FIXA: produção só usa .standard())
    public func create(password: String) throws -> (VaultEnvelope, VaultSession) {
        guard !password.isEmpty else { throw VaultError.emptyPassword }   // B4
        return try create(password: password, kdf: .standard())
    }

    /// Interno: KDFParams arbitrários (testes usam parâmetros rápidos). A API pública fixa
    /// `.standard()`, então todo cofre real tem o MESMO custo (fecha o oráculo de timing).
    func create(password: String, kdf: KDFParams) throws -> (VaultEnvelope, VaultSession) {
        let mk = SymmetricKey(size: .bits256)
        let env = try makeEnvelope(masterKey: mk, password: password, kdf: kdf)
        return (env, VaultSession(masterKey: mk))
    }

    // MARK: - Abrir (trabalho constante + erro único)

    /// Deriva a PDK UMA vez (o custo Argon2id) e tenta TODOS os slots — sempre todos, sem curto-
    /// circuito, para o trabalho não depender de qual slot casa (nem de haver casamento). Devolve a
    /// MK do slot que abrir, ou `nil`. Erros de biometria do dispositivo sobem como
    /// `deviceAuthUnavailable`; material errado num slot simplesmente não abre aquele slot.
    private func unlockMasterKey(env: VaultEnvelope, password: String) throws -> SymmetricKey? {
        guard Vault.supportedVersions.contains(env.version),
              env.kdf.withinSaneBounds(),
              env.salt.count == KeyDerivation.saltLength,
              env.slots.count == VaultEnvelope.slotCount else {
            Vault.decoyWork(password: password)   // mesmo custo de um open real
            return nil
        }
        guard let pdk = try? KeyDerivation.deriveKey(password: password, salt: env.salt, params: env.kdf) else {
            return nil
        }
        let aadData = aad(for: env)
        var found: SymmetricKey?
        for slot in env.slots {
            let inner: Data
            do {
                inner = try device.unwrap(slot)
            } catch let e as DeviceKeystoreError {
                switch e {
                case .authenticationCancelled, .authenticationUnavailable:
                    throw VaultError.deviceAuthUnavailable   // fator dispositivo indisponível: vale p/ todos os slots
                case .corrupted:
                    continue                                 // slot-lixo/adulterado: não abre este, segue
                }
            } catch {
                continue
            }
            if let mkData = AEAD.open(inner, key: pdk, aad: aadData), found == nil {
                found = SymmetricKey(data: mkData)
            }
        }
        return found
    }

    public func open(envelope env: VaultEnvelope, password: String) throws -> VaultSession {
        guard let mk = try unlockMasterKey(env: env, password: password) else { throw VaultError.wrongPasswordOrNoVault }
        return VaultSession(masterKey: mk)
    }

    // MARK: - Cofre falso (decoy)

    /// Configura (ou re-atribui) o cofre falso: abre o cofre atual com `password`, identifica seu
    /// slot e grava, no OUTRO slot, um cofre novo sob `decoyPassword`. Devolve o envelope atualizado
    /// e a sessão do cofre falso (para semear conteúdo plausível). Deniável: não há flag persistida
    /// de "tem decoy"; o envelope continua com o mesmo nº de slots. A senha do falso deve diferir da
    /// real.
    public func setDecoy(envelope env: VaultEnvelope, password: String, decoyPassword: String) throws -> (VaultEnvelope, VaultSession) {
        guard !decoyPassword.isEmpty else { throw VaultError.emptyPassword }
        guard Vault.supportedVersions.contains(env.version),
              env.kdf.withinSaneBounds(),
              env.salt.count == KeyDerivation.saltLength,
              env.slots.count == VaultEnvelope.slotCount else { throw VaultError.corrupted }

        let aadData = aad(for: env)
        let realPDK = try KeyDerivation.deriveKey(password: password, salt: env.salt, params: env.kdf)
        // Acha o índice do slot que a senha real abre. `unwrap` distingue B6: indisponibilidade do
        // Enclave sobe como `.deviceAuthUnavailable` (não vira "senha errada" espúria); slot-lixo
        // apenas não abre.
        var realIdx: Int?
        for (i, slot) in env.slots.enumerated() {
            let inner: Data
            do { inner = try device.unwrap(slot) }
            catch let e as DeviceKeystoreError {
                if case .corrupted = e { continue }
                throw VaultError.deviceAuthUnavailable
            }
            if AEAD.open(inner, key: realPDK, aad: aadData) != nil { realIdx = i; break }
        }
        guard let realIdx else { throw VaultError.wrongPasswordOrNoVault }

        let decoyPDK = try KeyDerivation.deriveKey(password: decoyPassword, salt: env.salt, params: env.kdf)
        // Rejeita senha do falso == senha real (abriria o mesmo slot; não faria sentido).
        if let inner = try? device.unwrap(env.slots[realIdx]),
           AEAD.open(inner, key: decoyPDK, aad: aadData) != nil {
            throw VaultError.invalidArgument
        }
        // Grava o decoy no primeiro slot que NÃO é o real (agnóstico ao nº de slots; os demais
        // seguem lixo). Preserva o slot real.
        guard let otherIdx = env.slots.indices.first(where: { $0 != realIdx }) else { throw VaultError.corrupted }
        let decoyMK = SymmetricKey(size: .bits256)
        var updated = env
        updated.slots[otherIdx] = try sealSlot(masterKey: decoyMK, pdk: decoyPDK, aad: aadData)
        return (updated, VaultSession(masterKey: decoyMK))
    }

    /// Boundary ÚNICO de persistência: decodifica o envelope do disco e unifica QUALQUER falha
    /// (inclusive `DecodingError` de blob truncado/corrompido) em `.wrongPasswordOrNoVault`,
    /// pagando o custo de isca. As gavetas SEMPRE carregam por aqui (correção B5/regressão-decode).
    public func open(fromEnvelopeData data: Data, password: String) throws -> VaultSession {
        guard let env = try? JSONDecoder().decode(VaultEnvelope.self, from: data) else {
            Vault.decoyWork(password: password)
            throw VaultError.wrongPasswordOrNoVault
        }
        return try open(envelope: env, password: password)
    }

    public func encodeEnvelope(_ env: VaultEnvelope) throws -> Data {
        try JSONEncoder().encode(env)
    }

    // MARK: - Trocar senha (re-wrap SÓ do slot que casa; preserva o outro cofre)
    public func changePassword(envelope env: VaultEnvelope, oldPassword: String, newPassword: String) throws -> VaultEnvelope {
        guard !newPassword.isEmpty else { throw VaultError.emptyPassword }
        return try changePassword(envelope: env, oldPassword: oldPassword, newPassword: newPassword, kdf: .standard())
    }

    /// Re-embrulha, no lugar, APENAS o slot que `oldPassword` abre — o outro slot (p.ex. o cofre
    /// falso) fica intacto. Salt/KDF são compartilhados pelos slots e não giram (não dá para
    /// re-embrulhar o slot cuja senha não temos). O parâmetro `kdf` é ignorado: usa-se o do envelope.
    func changePassword(envelope env: VaultEnvelope, oldPassword: String, newPassword: String, kdf: KDFParams) throws -> VaultEnvelope {
        guard Vault.supportedVersions.contains(env.version),
              env.kdf.withinSaneBounds(),
              env.salt.count == KeyDerivation.saltLength,
              env.slots.count == VaultEnvelope.slotCount else { throw VaultError.corrupted }
        let aadData = aad(for: env)
        let oldPDK = try KeyDerivation.deriveKey(password: oldPassword, salt: env.salt, params: env.kdf)
        var matchedIdx: Int?
        var mk: SymmetricKey?
        for (i, slot) in env.slots.enumerated() {
            let inner: Data
            do { inner = try device.unwrap(slot) }
            catch let e as DeviceKeystoreError {
                if case .corrupted = e { continue }
                throw VaultError.deviceAuthUnavailable   // B6: Enclave indisponível ≠ senha errada
            }
            if let mkData = AEAD.open(inner, key: oldPDK, aad: aadData) { matchedIdx = i; mk = SymmetricKey(data: mkData); break }
        }
        guard let matchedIdx, let mk else { throw VaultError.wrongPasswordOrNoVault }
        let newPDK = try KeyDerivation.deriveKey(password: newPassword, salt: env.salt, params: env.kdf)
        var updated = env
        updated.slots[matchedIdx] = try sealSlot(masterKey: mk, pdk: newPDK, aad: aadData)
        return updated
    }

    // MARK: - Frase de recuperação (2º envelope da MESMA MK, sob a frase)

    /// Cria um envelope de recuperação: a chave-mestra re-embrulhada sob a FRASE (não a senha).
    /// Guardado separado do envelope principal. Abrir com a frase recupera a MK.
    public func addRecovery(envelope env: VaultEnvelope, password: String, recoveryPhrase: String) throws -> VaultEnvelope {
        try addRecovery(envelope: env, password: password, recoveryPhrase: recoveryPhrase, kdf: .standard())
    }
    func addRecovery(envelope env: VaultEnvelope, password: String, recoveryPhrase: String, kdf: KDFParams) throws -> VaultEnvelope {
        guard !recoveryPhrase.isEmpty else { throw VaultError.emptyPassword }
        guard let mk = try unlockMasterKey(env: env, password: password) else { throw VaultError.wrongPasswordOrNoVault }
        return try makeEnvelope(masterKey: mk, password: recoveryPhrase, kdf: kdf)
    }

    /// Recupera com a frase: abre o envelope de recuperação e re-embrulha a MK sob uma senha NOVA,
    /// devolvendo o novo envelope PRINCIPAL + a sessão aberta (mesma MK → dados antigos intactos).
    /// NOTA: o novo envelope principal traz o cofre real + um slot-lixo; um cofre falso anterior é
    /// descartado (seus blobs ficam órfãos/indistinguíveis de aleatório). Refazer o decoy depois.
    public func recover(recoveryEnvelope recEnv: VaultEnvelope, phrase: String, newPassword: String) throws -> (VaultEnvelope, VaultSession) {
        try recover(recoveryEnvelope: recEnv, phrase: phrase, newPassword: newPassword, kdf: .standard())
    }
    func recover(recoveryEnvelope recEnv: VaultEnvelope, phrase: String, newPassword: String, kdf: KDFParams) throws -> (VaultEnvelope, VaultSession) {
        guard !newPassword.isEmpty else { throw VaultError.emptyPassword }
        guard let mk = try unlockMasterKey(env: recEnv, password: phrase) else { throw VaultError.wrongPasswordOrNoVault }
        let newMain = try makeEnvelope(masterKey: mk, password: newPassword, kdf: kdf)
        return (newMain, VaultSession(masterKey: mk))
    }

    /// Trabalho de isca para "cofre inexistente" — MESMO custo (`.standard()`) de um open real,
    /// para não vazar a ausência do cofre por timing (A3).
    public static func decoyWork(password: String) {
        _ = try? KeyDerivation.deriveKey(password: password,
                                         salt: (try? KeyDerivation.newSalt()) ?? [UInt8](repeating: 0, count: 16),
                                         params: .standard())
    }
}

/// Sessão de cofre aberta: mantém a chave-mestra em memória e faz cripto por-arquivo.
public final class VaultSession {
    private var masterKey: SymmetricKey?
    init(masterKey: SymmetricKey) { self.masterKey = masterKey }
    deinit { masterKey = nil }

    public var isOpen: Bool { masterKey != nil }

    /// AAD canônico por-item (framing com domain-separator + comprimento explícito). `fileID`
    /// é OBRIGATÓRIO (sem default footgun) e amarra a FEK+ciphertext à identidade do item,
    /// impedindo relocar um blob válido entre gavetas/slots. Versionado (`item-v1`) para poder
    /// compor `fileID+drawerID` no futuro sem quebrar os arquivos já cifrados.
    static func itemAAD(fileID: String) -> Data {
        var d = Data("BLKH01E/item-v1".utf8)
        let id = Array(fileID.utf8)
        withUnsafeBytes(of: UInt32(id.count).bigEndian) { d.append(contentsOf: $0) }
        d.append(contentsOf: id)
        return d
    }

    /// Cifra conteúdo com uma chave-por-arquivo (FEK) fresca, amarrada ao `fileID`. Destruir só
    /// o `wrappedFileKey` crypto-shreda só este item.
    public func encryptFile(_ plaintext: Data, fileID: String) throws -> (wrappedFileKey: Data, ciphertext: Data) {
        guard let mk = masterKey else { throw VaultError.sessionClosed }
        let aad = VaultSession.itemAAD(fileID: fileID)
        let fek = SymmetricKey(size: .bits256)
        let ciphertext = try AEAD.seal(plaintext, key: fek, aad: aad)
        var fekData = fek.withUnsafeBytes { Data($0) }
        defer { fekData.resetBytes(in: 0..<fekData.count) }
        let wrappedFileKey = try AEAD.seal(fekData, key: mk, aad: aad)
        return (wrappedFileKey, ciphertext)
    }

    public func decryptFile(wrappedFileKey: Data, ciphertext: Data, fileID: String) throws -> Data {
        guard let mk = masterKey else { throw VaultError.sessionClosed }
        let aad = VaultSession.itemAAD(fileID: fileID)
        guard var fekData = AEAD.open(wrappedFileKey, key: mk, aad: aad) else { throw VaultError.corrupted }
        defer { fekData.resetBytes(in: 0..<fekData.count) }
        let fek = SymmetricKey(data: fekData)
        guard let plaintext = AEAD.open(ciphertext, key: fek, aad: aad) else { throw VaultError.corrupted }
        return plaintext
    }

    /// Chave de armazenamento (nome de blob) derivada da MK via HMAC-SHA256 sobre um rótulo lógico.
    /// Dois cofres (real e falso) têm MKs independentes → chaves de blob totalmente disjuntas e sem
    /// prefixo comum, então um perito NÃO consegue agrupar os blobs por cofre nem contar quantos
    /// cofres têm conteúdo. Determinística (mesmo rótulo → mesma chave) e opaca (base64url, segura
    /// para nome de arquivo).
    public func storageKey(_ label: String) throws -> String {
        guard let mk = masterKey else { throw VaultError.sessionClosed }
        let mac = HMAC<SHA256>.authenticationCode(for: Data("BLKH01E/store-key/v1/\(label)".utf8), using: mk)
        return Data(mac).base64URLString()
    }

    /// A chave-mestra em claro. `internal` e de nome feio DE PROPÓSITO: o ÚNICO consumidor legítimo
    /// é o `VaultArchive`, que precisa re-embrulhar a MK sob a frase-de-export (sem o fator-
    /// dispositivo — é isso que torna o arquivo portátil). Nunca tornar público: a API pública do
    /// cofre não deve ter como extrair a MK.
    func masterKeyForArchive() throws -> SymmetricKey {
        guard let mk = masterKey else { throw VaultError.sessionClosed }
        return mk
    }

    /// Remove a chave-mestra da memória. Limite honesto: ARC/Swift não garante zeroização total.
    public func close() { masterKey = nil }
}

private extension Data {
    /// base64url sem padding: seguro para nome de arquivo (sem `/`, `+`, `=`).
    func base64URLString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
