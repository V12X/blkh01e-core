import Foundation
import CryptoKit

public enum ArchiveError: Error, Equatable {
    case malformed                  // não é um arquivo BLKH01E válido / truncado
    case unsupportedVersion
    case wrongPassphraseOrCorrupt   // AEAD falhou (frase errada ou adulteração) — erro ÚNICO
    case emptyPassphrase
    case tooLarge                   // acima do teto de RAM do v1
    case sessionClosed
}

/// Arquivo PORTÁTIL do cofre (`.blkh01e`): a única forma de o conteúdo sobreviver à perda do
/// aparelho. Feito para AirDrop/Arquivos/pendrive — sem servidor, sem nuvem, ato explícito do dono.
///
/// ================== FORMATO v1 — CONGELADO ==================
///   header    = magic "BHA1"(4) | version(1) | reserved(1)=0 | opsLimit(u32 BE) | memLimit(u32 BE)
///               | salt(16)                                                        [30 bytes]
///   corpo     = [u32 len][AEAD(MK,        key=EK, aad=header)]   ← EK = Argon2id(frase, salt)
///               [u32 len][AEAD(diretório, key=MK, aad=header)]   ← nomes lógicos + tamanhos
///               [blob][blob]…                                    ← já são ciphertext sob a MK
/// Qualquer mudança neste layout exige `version` novo. AAD = header inteiro (fecha downgrade).
/// ============================================================
///
/// **TETO HONESTO — dito na UI, não só aqui:** o arquivo é protegido pela FRASE SOZINHA. O fator-
/// dispositivo (Secure Enclave) fica de fora POR CONSTRUÇÃO — é ele que prende o cofre a um
/// aparelho, e o objetivo aqui é justamente escapar disso. Consequência: arquivo vazado + frase
/// fraca = cofre inteiro aberto, offline, sem limite de tentativas além do Argon2id. A frase do
/// arquivo tem de ser tão forte quanto o conteúdo é sensível.
///
/// **Deniabilidade:** exporta-se o cofre ABERTO, e só os blobs alcançáveis pelo índice dele. Levar
/// "todos os blobs" do BlobStore (que é compartilhado entre real e falso) entregaria, a quem tem o
/// arquivo e a frase, blobs que não batem com o índice — prova da existência do segundo cofre.
/// Cada arquivo é o retrato de UM cofre e nada nele diz se era o real ou o falso.
public enum VaultArchive {
    private static let magic = Data("BHA1".utf8)
    private static let version1: UInt8 = 1
    private static let headerLen = 4 + 1 + 1 + 4 + 4 + 16   // 30

    /// Teto de RAM do v1: o arquivo é montado inteiro em memória. Streaming é evolução — até lá,
    /// falhar com mensagem clara é melhor do que ser morto pelo jetsam no meio do export.
    public static let maxArchiveBytes = 200_000_000

    /// Rótulos lógicos (não as chaves derivadas): o diretório vai CIFRADO sob a MK, então os nomes
    /// não vazam; e na importação as chaves de blob são re-derivadas da MK (mesma MK → mesmas chaves).
    struct Entry: Codable, Equatable {
        var label: String
        var size: Int
    }

    // MARK: - Exportar

    public static func export(session: VaultSession, items: [VaultItem],
                              blobs: BlobStore, passphrase: String) throws -> Data {
        try export(session: session, items: items, blobs: blobs, passphrase: passphrase, params: .standard())
    }

    /// Interno: KDF arbitrário (testes usam rápido). A API pública fixa `.standard()`.
    static func export(session: VaultSession, items: [VaultItem], blobs: BlobStore,
                       passphrase: String, params: KDFParams) throws -> Data {
        guard !passphrase.isEmpty else { throw ArchiveError.emptyPassphrase }
        let mk = try session.masterKeyForArchive()

        let salt = try KeyDerivation.newSalt()
        let ek = try KeyDerivation.deriveKey(password: passphrase, salt: salt, params: params)

        var header = Data(capacity: headerLen)
        header.append(magic)
        header.append(version1)
        header.append(0)                                   // reservado
        appendU32(&header, UInt32(params.opsLimit))
        appendU32(&header, UInt32(params.memLimit))
        header.append(contentsOf: salt)

        // A MK re-embrulhada SÓ sob a frase (sem fator-dispositivo → portátil).
        var mkData = mk.withUnsafeBytes { Data($0) }
        defer { mkData.resetBytes(in: 0..<mkData.count) }
        let wrappedMK = try AEAD.seal(mkData, key: ek, aad: header)

        // Só o que o índice DESTE cofre alcança (ver nota de deniabilidade).
        var labels = ["index"]
        labels.append(contentsOf: items.map { "content/\($0.id)" })

        var entries: [Entry] = []
        var bodies: [Data] = []
        var total = 0
        for label in labels {
            guard let d = try blobs.get(try session.storageKey(label)) else { continue }
            total += d.count
            guard total <= maxArchiveBytes else { throw ArchiveError.tooLarge }
            entries.append(Entry(label: label, size: d.count))
            bodies.append(d)
        }

        let sealedDir = try AEAD.seal(try JSONEncoder().encode(entries), key: mk, aad: header)

        var out = Data(capacity: headerLen + wrappedMK.count + sealedDir.count + total + 8)
        out.append(header)
        appendU32(&out, UInt32(wrappedMK.count)); out.append(wrappedMK)
        appendU32(&out, UInt32(sealedDir.count)); out.append(sealedDir)
        for b in bodies { out.append(b) }
        return out
    }

    // MARK: - Importar

    /// Abre o arquivo com a frase, grava os blobs no BlobStore local e cria um envelope principal
    /// NOVO para este aparelho (MK do arquivo + fator-dispositivo local + `newPassword`).
    /// Devolve o envelope (para o app persistir) e a sessão já aberta.
    ///
    /// NOTA: o cofre importado NÃO tem cofre falso — o arquivo é o retrato de um cofre só. Refazer
    /// o decoy depois, em Ajustes, se quiser.
    public static func restore(_ archive: Data, passphrase: String, into blobs: BlobStore,
                               device: DeviceKeystore, newPassword: String) throws -> (VaultEnvelope, VaultSession) {
        try restore(archive, passphrase: passphrase, into: blobs, device: device,
                    newPassword: newPassword, kdf: .standard())
    }

    static func restore(_ archive: Data, passphrase: String, into blobs: BlobStore,
                        device: DeviceKeystore, newPassword: String, kdf: KDFParams) throws -> (VaultEnvelope, VaultSession) {
        guard !passphrase.isEmpty else { throw ArchiveError.emptyPassphrase }
        guard !newPassword.isEmpty else { throw ArchiveError.emptyPassphrase }
        guard archive.count >= headerLen + 8 else { throw ArchiveError.malformed }

        let header = archive.subdata(in: 0..<headerLen)
        guard header.subdata(in: 0..<4) == magic else { throw ArchiveError.malformed }
        guard header[4] == version1 else { throw ArchiveError.unsupportedVersion }

        let ops = Int(readU32(header.subdata(in: 6..<10)))
        let mem = Int(readU32(header.subdata(in: 10..<14)))
        let salt = Array(header.subdata(in: 14..<30))
        let params = KDFParams(opsLimit: ops, memLimit: mem, algorithm: 1)
        // Anti-DoS: o custo vem de um arquivo que pode ser hostil; o único produtor legítimo usa
        // `.standard()`, então TETAMOS ali (mesma regra do SecureMessage).
        let std = KDFParams.standard()
        guard params.withinSaneBounds(),
              params.opsLimit <= std.opsLimit,
              params.memLimit <= std.memLimit else { throw ArchiveError.malformed }

        var off = headerLen
        guard let wrappedMK = try readChunk(archive, &off) else { throw ArchiveError.malformed }
        guard let sealedDir = try readChunk(archive, &off) else { throw ArchiveError.malformed }

        guard let ek = try? KeyDerivation.deriveKey(password: passphrase, salt: salt, params: params),
              var mkData = AEAD.open(wrappedMK, key: ek, aad: header) else {
            throw ArchiveError.wrongPassphraseOrCorrupt
        }
        defer { mkData.resetBytes(in: 0..<mkData.count) }
        guard mkData.count == 32 else { throw ArchiveError.wrongPassphraseOrCorrupt }
        let mk = SymmetricKey(data: mkData)

        guard let dirData = AEAD.open(sealedDir, key: mk, aad: header),
              let entries = try? JSONDecoder().decode([Entry].self, from: dirData) else {
            throw ArchiveError.wrongPassphraseOrCorrupt
        }

        // Sessão temporária só para re-derivar as chaves de blob (mesma MK → mesmas chaves).
        let session = VaultSession(masterKey: mk)
        for e in entries {
            guard e.size >= 0, off + e.size <= archive.count else { throw ArchiveError.malformed }
            let data = archive.subdata(in: off..<(off + e.size))
            off += e.size
            try blobs.put(try session.storageKey(e.label), data)
        }

        // Envelope principal DESTE aparelho: MK adotada + fator-dispositivo local + senha nova.
        let vault = Vault(device: device)
        let env = try vault.makeEnvelope(masterKey: mk, password: newPassword, kdf: kdf)
        return (env, session)
    }

    // MARK: - Helpers

    /// Lê `[u32 len][bytes]` com verificação de limites (nada de leitura fora do buffer).
    private static func readChunk(_ d: Data, _ off: inout Int) throws -> Data? {
        guard off + 4 <= d.count else { return nil }
        let len = Int(readU32(d.subdata(in: off..<(off + 4))))
        off += 4
        guard len >= 0, off + len <= d.count else { return nil }
        let out = d.subdata(in: off..<(off + len))
        off += len
        return out
    }

    private static func appendU32(_ d: inout Data, _ v: UInt32) {
        var be = v.bigEndian
        withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
    }
    private static func readU32(_ d: Data) -> UInt32 {
        d.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian
    }
}
