import Foundation
import CryptoKit
import Sodium

/// Ingestão anônima (crypto_box_seal). A Share Extension roda SEM a chave-mestra; ela sela o
/// conteúdo recebido para a CHAVE PÚBLICA de ingestão do cofre (remetente efêmero e anônimo — a
/// pública não é segredo). Só o app principal, com a chave SECRETA (embrulhada sob a MK), abre
/// depois de desbloquear. Assim NADA em claro fica na staging do App Group, nem por um instante.
///
/// Este é também o groundwork do futuro `mode` 2 (mensagens por chave pública).
public enum IngestSeal {
    public struct Keypair: Equatable, Sendable {
        public let publicKey: Data   // 32 B — vai para o App Group (pública)
        public let secretKey: Data   // 32 B — embrulhada sob a MK
        public init(publicKey: Data, secretKey: Data) {
            self.publicKey = publicKey; self.secretKey = secretKey
        }
        /// Serialização para guardar sob a MK: `sk || pk` (64 B). A pública viaja junto para o par
        /// ser reconstituído SEM depender do arquivo compartilhado (que pode ser de outro cofre).
        public var stored: Data { secretKey + publicKey }
    }

    /// Quem é "dono" da ingestão. A inbox e a chave pública são COMPARTILHADAS entre o cofre real e
    /// o falso, então a decisão de gerar/publicar par não pode ser cega (foi o bug C1: abrir o decoy
    /// sobrescrevia a pública do real). Regra: quem tem par guardado usa o seu; senão, só vira dono
    /// se ainda não há pública válida publicada — do contrário deixa para o outro cofre.
    public enum Ownership: Equatable {
        case useStored      // este cofre já tem par → usa (e republica a pública só se sumiu)
        case becomeOwner    // ninguém publicou pública válida → este cofre gera e publica
        case deferToOther   // outro cofre já é dono → este NÃO participa (não clobbera)
    }

    public static func ownership(hasStoredKeypair: Bool, publishedPublicKeyValid: Bool) -> Ownership {
        if hasStoredKeypair { return .useStored }
        return publishedPublicKeyValid ? .deferToOther : .becomeOwner
    }

    /// Reconstrói o par a partir do blob guardado sob a MK (`sk || pk`, 64 B). `nil` se o tamanho
    /// não bate — ex.: dado antigo/corrompido, que NÃO deve virar um par silenciosamente incompatível.
    public static func keypair(fromStored blob: Data) -> Keypair? {
        guard blob.count == 64 else { return nil }
        return Keypair(publicKey: Data(blob.suffix(32)), secretKey: Data(blob.prefix(32)))
    }

    public static func newKeypair() -> Keypair? {
        guard let kp = Sodium().box.keyPair() else { return nil }
        return Keypair(publicKey: Data(kp.publicKey), secretKey: Data(kp.secretKey))
    }

    /// Sela `message` para a chave pública (anônimo). Usado pela EXTENSÃO.
    public static func seal(_ message: Data, to publicKey: Data) -> Data? {
        guard let sealed = Sodium().box.seal(message: Array(message),
                                             recipientPublicKey: Array(publicKey)) else { return nil }
        return Data(sealed)
    }

    /// Abre o blob selado com o par (pub+secret). Usado pelo APP PRINCIPAL após unlock.
    /// Retorna nil se a chave não bate ou o blob foi adulterado.
    public static func open(_ sealed: Data, keypair: Keypair) -> Data? {
        guard let opened = Sodium().box.open(anonymousCipherText: Array(sealed),
                                             recipientPublicKey: Array(keypair.publicKey),
                                             recipientSecretKey: Array(keypair.secretKey)) else { return nil }
        return Data(opened)
    }

    // MARK: - Fluxo v2 (streaming) — arquivos grandes sem estourar a RAM da extensão

    /// O v1 selava o item INTEIRO num JSON com o payload em base64: um vídeo de 60 MB virava
    /// ~5–6 cópias transitórias (~300 MB) dentro da extensão (limite ~120 MB) → morte por jetsam
    /// SEM erro, perdendo o item. No v2 só o HEADER (metadados + chave de conteúdo K) é selado
    /// para a pública; o payload é cifrado em CHUNKS sob K (AEAD ChaCha20-Poly1305), direto de
    /// arquivo para arquivo — pico de RAM ~1 chunk.
    ///
    /// Layout do blob:  magic "BHI2" | u32 len | box_seal(header) | { u32 len | AEAD_K(chunk) }…
    /// header (selado): u8 kind | u32 nameLen | nameUTF8 | u64 payloadLen | K(32)
    /// AAD do chunk i = "BHI2/chunk" + u32(i): chunk fora de ordem/duplicado não abre.
    /// `payloadLen` fecha truncamento: faltou byte → item inválido, nunca um prefixo "válido".
    /// Formato INTERNO da inbox (não congelado); o leitor mantém compat com blobs v1 pendentes.
    public struct StreamHeader: Equatable {
        public let kind: UInt8
        public let name: String
        public let payloadLen: UInt64
        public let contentKey: Data   // 32 B
        public init(kind: UInt8, name: String, payloadLen: UInt64, contentKey: Data) {
            self.kind = kind; self.name = name; self.payloadLen = payloadLen; self.contentKey = contentKey
        }
    }

    public static let streamMagic = Data("BHI2".utf8)
    /// Tamanho de chunk: grande o bastante para IO eficiente, pequeno o bastante para a extensão.
    public static let streamChunkSize = 4_000_000

    /// Chave de conteúdo fresca (32 B) para um item v2.
    public static func newContentKey() -> Data? {
        Sodium().randomBytes.buf(length: 32).map { Data($0) }
    }

    public static func sealStreamHeader(_ h: StreamHeader, to publicKey: Data) -> Data? {
        guard h.contentKey.count == 32 else { return nil }
        var plain = Data()
        plain.append(h.kind)
        let name = Data(h.name.utf8)
        withUnsafeBytes(of: UInt32(name.count).bigEndian) { plain.append(contentsOf: $0) }
        plain.append(name)
        withUnsafeBytes(of: h.payloadLen.bigEndian) { plain.append(contentsOf: $0) }
        plain.append(h.contentKey)
        return seal(plain, to: publicKey)
    }

    /// `nil` = não abre com este par (blob de outro cofre) OU header malformado.
    public static func openStreamHeader(_ sealed: Data, keypair: Keypair) -> StreamHeader? {
        guard let plain = open(sealed, keypair: keypair) else { return nil }
        var off = 0
        func take(_ n: Int) -> Data? {
            guard n >= 0, off + n <= plain.count else { return nil }
            defer { off += n }
            return plain.subdata(in: off..<(off + n))
        }
        guard let kindB = take(1),
              let nameLenB = take(4) else { return nil }
        let nameLen = Int(nameLenB.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) })
        guard nameLen <= 1024,
              let nameB = take(nameLen), let name = String(data: nameB, encoding: .utf8),
              let lenB = take(8) else { return nil }
        let payloadLen = lenB.withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(as: UInt64.self)) }
        guard let key = take(32), off == plain.count else { return nil }
        return StreamHeader(kind: kindB[0], name: name, payloadLen: payloadLen, contentKey: key)
    }

    private static func chunkAAD(_ index: UInt32) -> Data {
        var d = Data("BHI2/chunk".utf8)
        withUnsafeBytes(of: index.bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    public static func sealStreamChunk(_ chunk: Data, contentKey: Data, index: UInt32) -> Data? {
        guard contentKey.count == 32 else { return nil }
        return try? AEAD.seal(chunk, key: SymmetricKey(data: contentKey), aad: chunkAAD(index))
    }

    public static func openStreamChunk(_ sealed: Data, contentKey: Data, index: UInt32) -> Data? {
        guard contentKey.count == 32 else { return nil }
        return AEAD.open(sealed, key: SymmetricKey(data: contentKey), aad: chunkAAD(index))
    }
}
