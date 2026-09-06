import Foundation

/// As gavetas do cofre. A ORDEM define o grid da home (2 colunas). Adicionar casos é
/// retrocompatível: o `rawValue` é o nome do caso, então índices antigos continuam decodificando e
/// os novos gravam valores novos — sem migração.
public enum VaultDrawer: String, Codable, CaseIterable {
    case photosVideos   // Fotos e Vídeos
    case audios         // Áudios
    case textsDocs      // Documentos
    case passwords      // Senhas
    case links          // Links
    case contacts       // Contatos
    /// Bucket de armazenamento da FEATURE "Carteiras" (cripto). NÃO é uma pasta do grid — a UI a
    /// esconde e a expõe como área separada. Aditivo/retrocompatível (rawValue = nome do caso).
    case wallets
}

public enum ItemKind: String, Codable {
    case photo, video, text, document, link, password, audio
    /// Contato estruturado (ficha em JSON no conteúdo). Adicionar caso é retrocompatível: o
    /// rawValue é o nome do caso, então índices antigos (contato como `.text`) seguem decodificando;
    /// contatos novos gravam `.contact`. Sem migração.
    case contact
    /// Carteira cripto estruturada (rede/endereço/seed em JSON no conteúdo). Aditivo, sem migração.
    case wallet
}

/// Metadado de um item guardado. O `id` é o fileID estável (UUID) usado como AAD por-arquivo.
/// A `wrappedFileKey` é a chave-do-arquivo embrulhada sob a MK — some com ela = crypto-shred do item.
public struct VaultItem: Codable, Equatable, Identifiable {
    public var id: String
    public var drawer: VaultDrawer
    public var kind: ItemKind
    public var name: String
    public var size: Int
    public var createdAt: Double      // epoch (injetado; o núcleo não lê o relógio)
    public var wrappedFileKey: Data
    /// Prazo de autodestruição (epoch); `nil` = sem prazo. Opcional de propósito: índices antigos
    /// (sem o campo) decodificam como `nil` — retrocompatível, sem migração.
    public var expiresAt: Double?
    /// Subpasta (UM nível) dentro da gaveta; `nil` = raiz. Aditivo, retrocompatível: índices antigos
    /// decodificam como `nil` e o encoder omite `nil` (shape idêntico para quem não usa subpasta).
    public var folder: String?

    public init(id: String, drawer: VaultDrawer, kind: ItemKind, name: String, size: Int,
                createdAt: Double, wrappedFileKey: Data, expiresAt: Double? = nil, folder: String? = nil) {
        self.id = id; self.drawer = drawer; self.kind = kind
        self.name = name; self.size = size; self.createdAt = createdAt
        self.wrappedFileKey = wrappedFileKey; self.expiresAt = expiresAt; self.folder = folder
    }
}

/// Subpasta persistida de uma gaveta. Existe para que uma pasta VAZIA (criada mas ainda sem itens)
/// sobreviva — pastas com itens são deriváveis do `folder` dos próprios itens.
public struct VaultFolder: Codable, Equatable {
    public var drawer: VaultDrawer
    public var name: String
    public init(drawer: VaultDrawer, name: String) { self.drawer = drawer; self.name = name }
}

/// Armazenamento opaco de blobs cifrados, endereçados por chave. No app é o filesystem (arquivos
/// por nome derivado, `NSFileProtectionComplete`); nos testes/preview é em memória. Só ciphertext
/// chega aqui. CONTRATO: `put` DEVE ser atômico (temp+rename / `Data.write(.atomic)`).
public protocol BlobStore {
    func put(_ id: String, _ data: Data) throws
    func get(_ id: String) throws -> Data?
    /// Tamanho em bytes SEM carregar o conteúdo (nil = não existe). O export em streaming precisa
    /// do tamanho de cada blob antes de escrever os corpos; sem isto, leria o cofre inteiro duas
    /// vezes ou o manteria em RAM. Default no protocolo lê e conta; lojas em disco fazem `stat`.
    func size(_ id: String) throws -> Int?
    func delete(_ id: String) throws
    /// Crypto-shred TOTAL: apaga TODOS os blobs (panic-wipe). Destrói real E falso — o armazenamento
    /// é compartilhado. Some com a MK embrulhada (no envelope) → todo conteúdo vira ruído.
    func wipeAll() throws
}

public extension BlobStore {
    func size(_ id: String) throws -> Int? { try get(id)?.count }
    /// Existência SEM ler o conteúdo. O default (ler e descartar) é correto para qualquer store;
    /// o `FileBlobStore` do app sobrescreve com `fileExists` — o indexer da Busca Privada consulta
    /// isso por item a cada varredura, e não pode custar uma leitura inteira por consulta.
    func has(_ id: String) -> Bool { ((try? get(id)) ?? nil) != nil }
}

#if DEBUG
public final class InMemoryBlobStore: BlobStore {
    private var m: [String: Data] = [:]
    public init() {}
    public func put(_ id: String, _ data: Data) throws { m[id] = data }
    public func get(_ id: String) throws -> Data? { m[id] }
    public func delete(_ id: String) throws { m[id] = nil }
    public func wipeAll() throws { m.removeAll() }
}
#endif

/// Gerencia os itens de UM cofre: o índice cifrado (metadados) e o conteúdo por-arquivo.
///
/// `@MainActor` (correção A3): serializa todo acesso ao índice mutável, eliminando data race.
/// Operações de cripto pesadas com mídia grande devem ser feitas fora e só a mutação do store
/// aqui — refinar para `actor` se o custo no main thread incomodar.
@MainActor
public final class VaultStore {
    private let session: VaultSession
    private let blobs: BlobStore
    private var index: [VaultItem]
    private var folderList: [VaultFolder]   // registro de subpastas (persiste as vazias)

    // Nomes de blob DERIVADOS da MK (via `session.storageKey`) — não mais fixos. Assim dois cofres
    // (real e falso) compartilham o mesmo BlobStore com chaves disjuntas e sem prefixo comum:
    // impossível agrupar blobs por cofre ou contar cofres com conteúdo (deniabilidade no disco).
    // Os *fileID* abaixo continuam fixos: são só AAD por-item; a separação vem da MK na cifragem.
    private static let indexFileID = "__index__"
    private static let ingestFileID = "__ingest_sk__"
    private func indexKey() throws -> String { try session.storageKey("index") }
    private func ingestKey() throws -> String { try session.storageKey("ingest") }
    private func contentKey(_ id: String) throws -> String { try session.storageKey(Self.contentLabel(id)) }
    private func thumbKey(_ id: String) throws -> String { try session.storageKey("thumb/\(id)") }
    private static func thumbFileID(_ id: String) -> String { "thumb/\(id)" }

    /// Rótulo LÓGICO do blob de conteúdo de um item (o nome real vem de `session.storageKey`).
    /// Público e `nonisolated` de propósito: o app captura sessão+blobs e decifra itens grandes em
    /// task DESTACADA (fora do MainActor) — o store não participa para não prender a main thread.
    public nonisolated static func contentLabel(_ id: String) -> String { "content/\(id)" }

    /// CONTRATO de carga do índice (distinção deliberada entre AUSENTE e ILEGÍVEL):
    /// - blob ausente → cofre novo (ou cofre falso que nunca gravou nada): índice vazio.
    /// - blob PRESENTE mas ilegível (truncado/`len` forjado/AEAD falha/JSON inválido) → `.corrupted`.
    ///
    /// Abrir "vazio" no 2º caso mascararia perda de dados E seria destrutivo: o próximo `add`
    /// chamaria `persistIndex()`, sobrescrevendo o índice corrompido e orfanando TODOS os blobs
    /// (que, sem a `wrappedFileKey` do índice, são indistinguíveis de aleatório — irrecuperáveis).
    /// Falhar alto deixa o disco intacto para uma tentativa de perícia/recuperação.
    /// Nota: um cofre alheio (real vs. falso) NÃO cai aqui — a `storageKey` dele é outra, então o
    /// blob simplesmente não existe para esta sessão.
    public init(session: VaultSession, blobs: BlobStore) throws {
        self.session = session
        self.blobs = blobs
        self.folderList = []
        if let blob = try blobs.get(try session.storageKey("index")) {
            guard let (wf, ct) = Self.unpackBlob(blob) else { throw VaultError.corrupted }
            let data = try session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.indexFileID)
            guard let items = try? JSONDecoder().decode([VaultItem].self, from: data) else {
                throw VaultError.corrupted   // unifica DecodingError no erro do núcleo
            }
            self.index = items
        } else {
            self.index = []   // cofre novo (ou falso que nunca gravou nada)
        }
        // Registro de subpastas (opcional). NÃO falha alto: uma pasta vazia perdida é cosmética,
        // ≠ perda de conteúdo (as pastas com itens são deriváveis do `folder` dos itens).
        if let fblob = try? blobs.get(try session.storageKey("folders")),
           let (wf, ct) = Self.unpackBlob(fblob),
           let data = try? session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.foldersFileID),
           let list = try? JSONDecoder().decode([VaultFolder].self, from: data) {
            self.folderList = list
        }
    }

    public func items(in drawer: VaultDrawer? = nil) -> [VaultItem] {
        guard let d = drawer else { return index }
        return index.filter { $0.drawer == d }
    }

    /// Adiciona um item. Validações ANTES de qualquer efeito colateral (A5/A7). Ordem: conteúdo
    /// primeiro, índice depois — um crash deixa no máximo um blob órfão, nunca entrada apontando
    /// para conteúdo ausente (A6/A8). RAM e disco ficam consistentes mesmo em falha.
    @discardableResult
    public func add(content: Data, kind: ItemKind, drawer: VaultDrawer, name: String,
                    createdAt: Double, id: String, expiresAt: Double? = nil, folder: String? = nil) throws -> VaultItem {
        guard !id.isEmpty, !name.isEmpty, createdAt.isFinite else { throw VaultError.invalidArgument }
        if let e = expiresAt {
            // Prazo no passado (ou não-finito) nasceria já destruído: erro de chamada, não estado.
            guard e.isFinite, e > createdAt else { throw VaultError.invalidArgument }
        }
        guard !index.contains(where: { $0.id == id }) else { throw VaultError.invalidArgument }

        let (wf, ct) = try session.encryptFile(content, fileID: id)
        let ckey = try contentKey(id)
        try blobs.put(ckey, ct)
        let cleanFolder = folder?.trimmingCharacters(in: .whitespacesAndNewlines)
        let item = VaultItem(id: id, drawer: drawer, kind: kind, name: name, size: content.count,
                             createdAt: createdAt, wrappedFileKey: wf, expiresAt: expiresAt,
                             folder: (cleanFolder?.isEmpty ?? true) ? nil : cleanFolder)
        index.append(item)
        do {
            try persistIndex()
        } catch {
            index.removeLast()                             // mantém RAM == disco
            try? blobs.delete(ckey)                        // limpa o órfão
            throw error
        }
        return item
    }

    /// Arquivo portátil DESTE cofre (só o que o índice daqui alcança — ver `VaultArchive`).
    /// Fica aqui porque o store é quem tem sessão + índice + blobs; o app não precisa (nem deve)
    /// tocar na sessão para exportar.
    public func exportArchive(passphrase: String) throws -> Data {
        try VaultArchive.export(session: session, items: index, blobs: blobs, passphrase: passphrase)
    }

    public func read(_ item: VaultItem) throws -> Data {
        guard let ct = try blobs.get(try contentKey(item.id)) else { throw VaultError.corrupted }
        return try session.decryptFile(wrappedFileKey: item.wrappedFileKey, ciphertext: ct, fileID: item.id)
    }

    // MARK: - Miniatura cifrada persistente (por-item; regenerável, não viaja no arquivo)

    /// Guarda uma miniatura já pronta (JPEG) cifrada, num blob separado do original. A grade lê essa
    /// miniatura pequena (~10 KB) em vez de decifrar o original inteiro a cada sessão.
    public func setThumbnail(_ data: Data, for id: String) throws {
        let (wf, ct) = try session.encryptFile(data, fileID: Self.thumbFileID(id))
        try blobs.put(try thumbKey(id), Self.packBlob(wf: wf, ct: ct))
    }

    public func thumbnail(for id: String) throws -> Data? {
        guard let blob = try blobs.get(try thumbKey(id)), let (wf, ct) = Self.unpackBlob(blob) else { return nil }
        return try session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.thumbFileID(id))
    }

    /// Crypto-shred: comita a remoção da `wrappedFileKey` do índice PRIMEIRO (A8), só então apaga
    /// o ciphertext. Um crash no meio deixa no máximo um órfão; a FEK já foi destruída.
    public func delete(_ id: String) throws {
        guard let idx = index.firstIndex(where: { $0.id == id }) else { return }
        let removed = index.remove(at: idx)
        do {
            try persistIndex()
        } catch {
            index.insert(removed, at: idx)                 // rollback RAM
            throw error
        }
        if let ckey = try? contentKey(id) { try? blobs.delete(ckey) }
        if let tkey = try? thumbKey(id) { try? blobs.delete(tkey) }     // miniatura junto
        if let ekey = try? extractKey(id) { try? blobs.delete(ekey) }   // texto extraído junto
        if let mkey = try? embedKey(id) { try? blobs.delete(mkey) }     // vetor semântico junto
    }

    /// Autodestruição (burn Nível A): crypto-shreda TODO item cujo prazo venceu. `now` é injetado —
    /// o núcleo não lê o relógio. Mesma ordem do `delete` (A8): comita a remoção das
    /// `wrappedFileKey` do índice PRIMEIRO (um só persist), só então apaga os ciphertexts — um
    /// crash no meio deixa no máximo órfãos, nunca item "vivo" com prazo vencido.
    /// TETO HONESTO (rotulado na UI): roda quando o app roda — item vencido com o app fechado
    /// morre na PRÓXIMA abertura, não no instante do prazo (iOS não dá background garantido).
    @discardableResult
    public func purgeExpired(now: Double) throws -> Int {
        let expiredIDs = Set(index.filter { item in
            guard let e = item.expiresAt else { return false }
            return e <= now
        }.map(\.id))
        guard !expiredIDs.isEmpty else { return 0 }

        let old = index
        index.removeAll { expiredIDs.contains($0.id) }
        do {
            try persistIndex()
        } catch {
            index = old                                    // rollback RAM (RAM == disco)
            throw error
        }
        for id in expiredIDs {
            if let ckey = try? contentKey(id) { try? blobs.delete(ckey) }
            if let tkey = try? thumbKey(id) { try? blobs.delete(tkey) }
            if let ekey = try? extractKey(id) { try? blobs.delete(ekey) }
            if let mkey = try? embedKey(id) { try? blobs.delete(mkey) }
        }
        return expiredIDs.count
    }

    /// Renomeia um item. Só mexe no METADADO `name` do índice (cifrado) — o `id`/fileID e a AAD do
    /// conteúdo ficam estáveis, então o blob não é tocado. Persist atômico com rollback (RAM==disco).
    public func rename(_ id: String, to newName: String) throws {
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultError.invalidArgument }
        guard let i = index.firstIndex(where: { $0.id == id }) else { throw VaultError.invalidArgument }
        guard index[i].name != trimmed else { return }
        let old = index[i].name
        index[i].name = trimmed
        do {
            try persistIndex()
        } catch {
            index[i].name = old
            throw error
        }
    }

    public func move(_ id: String, to drawer: VaultDrawer) throws {
        guard let i = index.firstIndex(where: { $0.id == id }) else { throw VaultError.invalidArgument }
        let old = index[i].drawer
        guard old != drawer else { return }
        let oldFolder = index[i].folder
        index[i].drawer = drawer
        index[i].folder = nil   // a subpasta pertence à gaveta antiga; some ao trocar de gaveta
        do {
            try persistIndex()
        } catch {
            index[i].drawer = old; index[i].folder = oldFolder
            throw error
        }
    }

    // MARK: - Subpastas (UM nível por gaveta)

    private static let foldersFileID = "__folders__"
    private func foldersKey() throws -> String { try session.storageKey("folders") }

    private func persistFolders() throws {
        let data = try JSONEncoder().encode(folderList)
        let (wf, ct) = try session.encryptFile(data, fileID: Self.foldersFileID)
        try blobs.put(try foldersKey(), Self.packBlob(wf: wf, ct: ct))
    }

    /// Subpastas de uma gaveta: as do registro (inclui as VAZIAS) ∪ as derivadas dos itens (cobre
    /// itens vindos de um arquivo importado, cujo registro não viaja). Ordenadas por nome.
    public func folders(in drawer: VaultDrawer) -> [String] {
        var set = Set(folderList.filter { $0.drawer == drawer }.map(\.name))
        for it in index where it.drawer == drawer { if let f = it.folder, !f.isEmpty { set.insert(f) } }
        return set.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    /// Itens de uma gaveta numa subpasta (`folder = nil` → raiz da gaveta).
    public func items(in drawer: VaultDrawer, folder: String?) -> [VaultItem] {
        index.filter { $0.drawer == drawer && $0.folder == folder }
    }

    /// Cria uma subpasta vazia. Rejeita nome vazio ou duplicado (case-insensitive).
    public func createFolder(_ name: String, in drawer: VaultDrawer) throws {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultError.invalidArgument }
        guard !folders(in: drawer).contains(where: { $0.caseInsensitiveCompare(trimmed) == .orderedSame }) else {
            throw VaultError.invalidArgument
        }
        folderList.append(VaultFolder(drawer: drawer, name: trimmed))
        try persistFolders()
    }

    /// Renomeia uma subpasta: atualiza o registro E o `folder` de todos os itens dela. Persist dos
    /// dois com rollback (RAM == disco).
    public func renameFolder(_ old: String, to newName: String, in drawer: VaultDrawer) throws {
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, folders(in: drawer).contains(old) else { throw VaultError.invalidArgument }
        if trimmed.caseInsensitiveCompare(old) != .orderedSame,
           folders(in: drawer).contains(where: { $0.caseInsensitiveCompare(trimmed) == .orderedSame }) {
            throw VaultError.invalidArgument   // colidiria com outra pasta existente
        }
        let oldIndex = index, oldFolders = folderList
        for i in index.indices where index[i].drawer == drawer && index[i].folder == old { index[i].folder = trimmed }
        for i in folderList.indices where folderList[i].drawer == drawer && folderList[i].name == old { folderList[i].name = trimmed }
        do { try persistIndex(); try persistFolders() }
        catch { index = oldIndex; folderList = oldFolders; throw error }
    }

    /// Apaga a subpasta: os itens dela VOLTAM para a raiz (folder = nil); nada é destruído.
    public func deleteFolder(_ name: String, in drawer: VaultDrawer) throws {
        let oldIndex = index, oldFolders = folderList
        for i in index.indices where index[i].drawer == drawer && index[i].folder == name { index[i].folder = nil }
        folderList.removeAll { $0.drawer == drawer && $0.name == name }
        do { try persistIndex(); try persistFolders() }
        catch { index = oldIndex; folderList = oldFolders; throw error }
    }

    /// Move um item para uma subpasta (`folder = nil` → raiz). Persist atômico com rollback.
    public func move(_ id: String, toFolder folder: String?) throws {
        guard let i = index.firstIndex(where: { $0.id == id }) else { throw VaultError.invalidArgument }
        let clean = folder?.trimmingCharacters(in: .whitespacesAndNewlines)
        let target = (clean?.isEmpty ?? true) ? nil : clean
        let old = index[i].folder
        guard old != target else { return }
        index[i].folder = target
        do { try persistIndex() } catch { index[i].folder = old; throw error }
    }

    /// Persiste o índice como UM ÚNICO blob atômico (correção A1): `[u32 len(wf)][wf][ct]`,
    /// um só `put`. Elimina a dessincronia entre wf e ct por construção.
    // MARK: - Chave secreta de ingestão (fator do sealed box; cifrada sob a MK)

    /// Guarda a chave SECRETA de ingestão cifrada sob a MK. A PÚBLICA correspondente é gravada
    /// pelo app no App Group (em claro — é pública). Só quem tem a MK aberta lê a secreta.
    public func setIngestSecretKey(_ secret: Data) throws {
        let (wf, ct) = try session.encryptFile(secret, fileID: Self.ingestFileID)
        try blobs.put(try ingestKey(), Self.packBlob(wf: wf, ct: ct))
    }

    public func ingestSecretKey() throws -> Data? {
        guard let blob = try blobs.get(try ingestKey()), let (wf, ct) = Self.unpackBlob(blob) else { return nil }
        return try session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.ingestFileID)
    }

    // MARK: - Identidade de mensagem X25519 (sk||pk, 64 B; cifrada sob a MK)

    private static let identityFileID = "__msg_identity__"
    private func identityKey() throws -> String { try session.storageKey("msg-identity") }

    /// Guarda o par de identidade (sk||pk, 64 B) cifrado sob a MK. Some no crypto-shred do cofre.
    public func setMessageIdentity(_ blob: Data) throws {
        let (wf, ct) = try session.encryptFile(blob, fileID: Self.identityFileID)
        try blobs.put(try identityKey(), Self.packBlob(wf: wf, ct: ct))
    }

    public func messageIdentity() throws -> Data? {
        guard let blob = try blobs.get(try identityKey()), let (wf, ct) = Self.unpackBlob(blob) else { return nil }
        return try session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.identityFileID)
    }

    // MARK: - Chaveiro de contatos (nome → chave pública), cifrado sob a MK

    private static let keyringFileID = "__msg_keyring__"
    private func keyringKey() throws -> String { try session.storageKey("msg-keyring") }

    public func setKeyring(_ blob: Data) throws {
        let (wf, ct) = try session.encryptFile(blob, fileID: Self.keyringFileID)
        try blobs.put(try keyringKey(), Self.packBlob(wf: wf, ct: ct))
    }

    public func keyring() throws -> Data? {
        guard let blob = try blobs.get(try keyringKey()), let (wf, ct) = Self.unpackBlob(blob) else { return nil }
        return try session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.keyringFileID)
    }

    // MARK: - Frase do backup automático, cifrada sob a MK

    private static let backupPhraseFileID = "__backup_phrase__"
    private func backupPhraseKey() throws -> String { try session.storageKey("backup-phrase") }

    /// Guarda a frase do backup automático (o app re-gera o arquivo sem pedir digitação a cada vez).
    /// Cifrada sob a MK: só existe com o cofre aberto; morre no crypto-shred. NÃO viaja no arquivo
    /// `.blkh01e` (o export leva só blobs alcançáveis pelo índice de itens) — o backup nunca
    /// carrega a própria chave.
    public func setBackupPhrase(_ phrase: String) throws {
        let (wf, ct) = try session.encryptFile(Data(phrase.utf8), fileID: Self.backupPhraseFileID)
        try blobs.put(try backupPhraseKey(), Self.packBlob(wf: wf, ct: ct))
    }

    public func backupPhrase() throws -> String? {
        guard let blob = try blobs.get(try backupPhraseKey()),
              let (wf, ct) = Self.unpackBlob(blob) else { return nil }
        let d = try session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.backupPhraseFileID)
        return String(data: d, encoding: .utf8)
    }

    public func deleteBackupPhrase() throws {
        try? blobs.delete(try backupPhraseKey())
    }

    // MARK: - Marcador de AutoFill ligado, sob a MK

    private static let autoFillFlagFileID = "__autofill_on__"
    private func autoFillFlagKey() throws -> String { try session.storageKey("autofill-on") }

    /// Liga/desliga o marcador de AutoFill DESTE cofre (deniável: vive cifrado sob a MK, some no
    /// crypto-shred; o app usa para reescrever o espelho no unlock). O espelho e sua chave (App
    /// Group / Keychain) são geridos pela camada de app.
    public func setAutoFillEnabled(_ on: Bool) throws {
        if on {
            let (wf, ct) = try session.encryptFile(Data([1]), fileID: Self.autoFillFlagFileID)
            try blobs.put(try autoFillFlagKey(), Self.packBlob(wf: wf, ct: ct))
        } else {
            try? blobs.delete(try autoFillFlagKey())
        }
    }

    public func autoFillEnabled() throws -> Bool {
        ((try? blobs.get(try autoFillFlagKey())) ?? nil) != nil
    }

    // MARK: - Preferência "manter Ao vivo ligado" (sob a MK)

    private static let liveDefaultFileID = "__live_default_on__"
    private func liveDefaultKey() throws -> String { try session.storageKey("live-default") }

    /// Liga/desliga a preferência de auto-ativar a sessão AO VIVO ao abrir uma conversa. Deniável
    /// (cifrada sob a MK, some no crypto-shred, não vaza no backup). É SÓ a preferência do usuário —
    /// o transporte em si continua opt-in e mostra o teto honesto sempre que ativo.
    public func setLiveDefault(_ on: Bool) throws {
        if on {
            let (wf, ct) = try session.encryptFile(Data([1]), fileID: Self.liveDefaultFileID)
            try blobs.put(try liveDefaultKey(), Self.packBlob(wf: wf, ct: ct))
        } else {
            try? blobs.delete(try liveDefaultKey())
        }
    }

    public func liveDefault() throws -> Bool {
        ((try? blobs.get(try liveDefaultKey())) ?? nil) != nil
    }

    // MARK: - Conversas Double Ratchet (por contato), cifradas sob a MK

    private func conversationKey(_ contactID: String) throws -> String { try session.storageKey("msg-conv/\(contactID)") }
    private static func conversationFileID(_ contactID: String) -> String { "__msg_conv_\(contactID)__" }

    /// Guarda a conversa (estado do ratchet + histórico) de um contato, cifrada sob a MK. Some no
    /// crypto-shred do cofre e não viaja no arquivo `.blkh01e` (é regenerável/local).
    public func setConversation(_ blob: Data, for contactID: String) throws {
        let (wf, ct) = try session.encryptFile(blob, fileID: Self.conversationFileID(contactID))
        try blobs.put(try conversationKey(contactID), Self.packBlob(wf: wf, ct: ct))
    }

    public func conversation(for contactID: String) throws -> Data? {
        guard let blob = try blobs.get(try conversationKey(contactID)),
              let (wf, ct) = Self.unpackBlob(blob) else { return nil }
        return try session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.conversationFileID(contactID))
    }

    public func deleteConversation(for contactID: String) throws {
        try? blobs.delete(try conversationKey(contactID))
    }

    // MARK: - Texto extraído (Busca Privada), por item, sob a MK

    /// Rótulo LÓGICO do blob de texto extraído (OCR/PDF/texto puro) de um item. Público e
    /// `nonisolated` pelo mesmo racional do `contentLabel`: a busca decifra esses blobs em task
    /// destacada, fora do MainActor, capturando sessão+blobs. É também o fileID (AAD) do blob.
    public nonisolated static func extractLabel(_ id: String) -> String { "extract/\(id)" }
    private func extractKey(_ id: String) throws -> String { try session.storageKey(Self.extractLabel(id)) }

    /// Guarda o texto extraído de um item, cifrado sob a MK num blob separado do original.
    /// Regenerável e local: NÃO viaja no `.blkh01e` (o export leva só blobs alcançáveis pelo índice
    /// de itens) e é crypto-shreddado junto com o item no `delete`/`purgeExpired`. String VAZIA é
    /// válida e significa "processado, nada legível" — evita reprocessar o item a cada unlock.
    /// Rejeita id fora do índice (não cria blob órfão).
    public func setExtractedText(_ text: String, for id: String) throws {
        guard index.contains(where: { $0.id == id }) else { throw VaultError.invalidArgument }
        let (wf, ct) = try session.encryptFile(Data(text.utf8), fileID: Self.extractLabel(id))
        try blobs.put(try extractKey(id), Self.packBlob(wf: wf, ct: ct))
    }

    public func extractedText(for id: String) throws -> String? {
        guard let blob = try blobs.get(try extractKey(id)), let (wf, ct) = Self.unpackBlob(blob) else { return nil }
        let d = try session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.extractLabel(id))
        return String(data: d, encoding: .utf8)
    }

    /// Existência sem decifrar: o indexer pergunta isso por item a cada varredura.
    public func hasExtractedText(for id: String) -> Bool {
        guard let key = try? extractKey(id) else { return false }
        return blobs.has(key)
    }

    public func deleteExtractedText(for id: String) throws {
        try? blobs.delete(try extractKey(id))
    }

    // MARK: - Vetor semântico (Busca Privada fase 2), por item, sob a MK

    /// Rótulo LÓGICO do blob de vetor semântico (embedding) de um item. Mesmo regime do
    /// `extractLabel`: público/`nonisolated` (a busca lê fora do MainActor), fileID = rótulo.
    /// O LAYOUT do payload é da camada de app (versão+dim+floats); o núcleo guarda opaco.
    public nonisolated static func embedLabel(_ id: String) -> String { "embed/\(id)" }
    private func embedKey(_ id: String) throws -> String { try session.storageKey(Self.embedLabel(id)) }

    /// Guarda o vetor semântico de um item (opaco), cifrado sob a MK. Regenerável e local:
    /// NÃO viaja no `.blkh01e` e morre com o item (delete/TTL/wipe). Payload VAZIO é válido
    /// ("processado, nada a embutir"). Rejeita id fora do índice.
    public func setEmbedding(_ payload: Data, for id: String) throws {
        guard index.contains(where: { $0.id == id }) else { throw VaultError.invalidArgument }
        let (wf, ct) = try session.encryptFile(payload, fileID: Self.embedLabel(id))
        try blobs.put(try embedKey(id), Self.packBlob(wf: wf, ct: ct))
    }

    public func embedding(for id: String) throws -> Data? {
        guard let blob = try blobs.get(try embedKey(id)), let (wf, ct) = Self.unpackBlob(blob) else { return nil }
        return try session.decryptFile(wrappedFileKey: wf, ciphertext: ct, fileID: Self.embedLabel(id))
    }

    public func hasEmbedding(for id: String) -> Bool {
        guard let key = try? embedKey(id) else { return false }
        return blobs.has(key)
    }

    public func deleteEmbedding(for id: String) throws {
        try? blobs.delete(try embedKey(id))
    }

    // MARK: - Marcador do check de senhas vazadas (opt-IN, sob a MK)

    private static let breachFlagFileID = "__breach_on__"
    private func breachFlagKey() throws -> String { try session.storageKey("breach-on") }

    /// Opt-IN da verificação de senhas vazadas (k-anonymity, camada de app). Default DESLIGADO =
    /// ausência de marcador — é a única chamada de rede do app fora do chat opt-in, então a
    /// polaridade é a inversa dos escopos de indexação. Deniável; morre no crypto-shred.
    public func setBreachCheckEnabled(_ on: Bool) throws {
        if on {
            let (wf, ct) = try session.encryptFile(Data([1]), fileID: Self.breachFlagFileID)
            try blobs.put(try breachFlagKey(), Self.packBlob(wf: wf, ct: ct))
        } else {
            try? blobs.delete(try breachFlagKey())
        }
    }

    public func breachCheckEnabled() -> Bool {
        guard let key = try? breachFlagKey() else { return false }
        return blobs.has(key)
    }

    // MARK: - Busca Privada: escopos de indexação (opt-out, sob a MK)

    /// Escopo de indexação de conteúdo. Aditivo (rawValue = nome do caso), como os enums do índice.
    /// `audios` entrou na fase 2a (transcrição) e `notes` na 2b (vetor semântico de notas/links/
    /// contatos) — marcadores antigos seguem valendo, caso novo nasce no default (LIGADO).
    public enum IndexScope: String, CaseIterable {
        case photos, documents, audios, notes
    }
    private func indexOffKey(_ scope: IndexScope) throws -> String {
        try session.storageKey("index-off/\(scope.rawValue)")
    }
    private static func indexOffFileID(_ scope: IndexScope) -> String { "index-off/\(scope.rawValue)" }

    /// Liga/desliga a indexação de um escopo DESTE cofre. Default LIGADO = ausência de marcador;
    /// o marcador persiste só o DESLIGADO, cifrado sob a MK (deniável, some no crypto-shred).
    /// Desligar NÃO apaga os textos já extraídos — o app faz o shred dos `extract/<id>` do escopo
    /// (ele tem a lista de itens; o store não decide política).
    public func setContentIndexing(_ on: Bool, scope: IndexScope) throws {
        if on {
            try? blobs.delete(try indexOffKey(scope))
        } else {
            let (wf, ct) = try session.encryptFile(Data([1]), fileID: Self.indexOffFileID(scope))
            try blobs.put(try indexOffKey(scope), Self.packBlob(wf: wf, ct: ct))
        }
    }

    public func contentIndexingEnabled(scope: IndexScope) -> Bool {
        guard let key = try? indexOffKey(scope) else { return true }   // falha de derivação = default
        return !blobs.has(key)
    }

    private func persistIndex() throws {
        let data = try JSONEncoder().encode(index)
        let (wf, ct) = try session.encryptFile(data, fileID: Self.indexFileID)
        try blobs.put(try indexKey(), Self.packBlob(wf: wf, ct: ct))
    }

    /// Empacota (wf, ct) num blob único atômico `[u32 len(wf)][wf][ct]`. Público e `nonisolated`
    /// pelo mesmo racional do `contentLabel`: a busca decifra blobs auxiliares (texto extraído) em
    /// task destacada, fora do MainActor, capturando sessão+blobs — o store não participa.
    public nonisolated static func packBlob(wf: Data, ct: Data) -> Data {
        var d = Data(capacity: 4 + wf.count + ct.count)
        var len = UInt32(wf.count).bigEndian
        withUnsafeBytes(of: &len) { d.append(contentsOf: $0) }
        d.append(wf)
        d.append(ct)
        return d
    }

    public nonisolated static func unpackBlob(_ data: Data) -> (Data, Data)? {
        guard data.count >= 4 else { return nil }
        let len = data.subdata(in: 0..<4).withUnsafeBytes { UInt32(bigEndian: $0.load(as: UInt32.self)) }
        let wfEnd = 4 + Int(len)
        guard len <= UInt32(data.count), data.count >= wfEnd else { return nil }
        return (data.subdata(in: 4..<wfEnd), data.subdata(in: wfEnd..<data.count))
    }
}
