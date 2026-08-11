import Foundation
import CryptoKit
import P256K

/// Modelo de evento Nostr (NIP-01) para o transporte da **sessão ao vivo**. É só o CANO: o `content`
/// carrega o bloco `BLKH01E.…` do ratchet (ciphertext + padding, formato congelado). O relay valida
/// a assinatura schnorr do evento; a segurança real das mensagens continua sendo o ratchet.
///
/// Chave de publicação EFÊMERA (secp256k1/schnorr, fresca por evento) — a identidade do cofre NUNCA
/// assina eventos, então o relay não correlaciona os eventos de uma dupla por autor. O elo é só a
/// `mailbox` (tag `#t`), que rotaciona por dia (ver `RelayRendezvous`).
///
/// ==================== EVENTO DE RELAY v1 — CONGELADO ====================
///   id      = sha256( JSON canônico [0,pubkey,created_at,kind,tags,content] )   // NIP-01
///   sig     = schnorr(id, chave efêmera)                                        // BIP-340
///   kind    = 9077 (regular/armazenado → buffer semi-assíncrono curto)
///   tags    = [["t", <mailbox hex 64>]]                                          // endereço da caixa
///   content = "BLKH01E.<v>.<b64url>"                                             // o bloco do ratchet
/// Mudar qualquer parte exige versão nova.
/// =======================================================================
public enum Nostr {
    /// Kind do evento da sessão ao vivo. Regular (1000–9999) = o relay armazena por um tempo, dando o
    /// buffer semi-assíncrono (o contato recebe ao ABRIR o app). Fingerprint por kind é um metadado
    /// menor (o conteúdo é opaco); documentado no teto honesto.
    public static let liveKind = 9077

    public struct SignedEvent: Equatable, Sendable {
        public let id: String     // 64 hex (sha256 da serialização canônica)
        public let json: String   // objeto JSON completo {id,pubkey,created_at,kind,tags,content,sig}
    }

    // MARK: - Serialização canônica (NIP-01) e id

    /// `[0,"pubkey",created_at,kind,[tags…],"content"]` — sem espaços, escape NIP-01. É exatamente
    /// isto que entra no sha256 do id.
    static func canonical(pubkey: String, createdAt: Int64, kind: Int,
                          tags: [[String]], content: String) -> String {
        var s = "[0,\"\(pubkey)\",\(createdAt),\(kind),"
        s += tagsJSON(tags)
        s += ",\"\(escape(content))\"]"
        return s
    }

    static func eventID(pubkey: String, createdAt: Int64, kind: Int,
                        tags: [[String]], content: String) -> String {
        let data = Data(canonical(pubkey: pubkey, createdAt: createdAt, kind: kind,
                                  tags: tags, content: content).utf8)
        return hex(Data(SHA256.hash(data: data)))
    }

    // MARK: - Assinar

    /// Assina com uma chave EFÊMERA fresca (produção). `nil` se a geração/assinatura falhar.
    public static func signEphemeral(kind: Int, tags: [[String]], content: String,
                                     createdAt: Int64) -> SignedEvent? {
        guard let key = try? P256K.Schnorr.PrivateKey() else { return nil }
        return sign(kind: kind, tags: tags, content: content, createdAt: createdAt, privateKey: key)
    }

    /// Assina com uma chave dada (usado nos testes p/ vetores determinísticos do id). A assinatura
    /// schnorr usa aleatoriedade auxiliar (BIP-340), então o `sig` varia; o `id` é determinístico.
    static func sign(kind: Int, tags: [[String]], content: String, createdAt: Int64,
                     privateKey: P256K.Schnorr.PrivateKey) -> SignedEvent? {
        let pubkey = hex(Data(privateKey.xonly.bytes))
        let canon = canonical(pubkey: pubkey, createdAt: createdAt, kind: kind, tags: tags, content: content)
        let digest = SHA256.hash(data: Data(canon.utf8))   // os 32 bytes do id
        let id = hex(Data(digest))
        guard let sig = try? privateKey.signature(for: digest) else { return nil }
        let sigHex = hex(sig.dataRepresentation)
        var j = "{\"id\":\"\(id)\",\"pubkey\":\"\(pubkey)\",\"created_at\":\(createdAt),"
        j += "\"kind\":\(kind),\"tags\":\(tagsJSON(tags)),"
        j += "\"content\":\"\(escape(content))\",\"sig\":\"\(sigHex)\"}"
        return SignedEvent(id: id, json: j)
    }

    // MARK: - Quadros do protocolo de relay

    public static func publishFrame(_ e: SignedEvent) -> String { "[\"EVENT\",\(e.json)]" }

    /// Filtro: eventos do nosso kind, nas caixas `mailboxes` (tag `#t`), desde `since`. `limit`
    /// tampa quanto o relay devolve (anti-afogamento).
    public static func reqFrame(subID: String, mailboxes: [String], since: Int64?, limit: Int) -> String {
        let t = "[" + mailboxes.map { "\"\($0)\"" }.joined(separator: ",") + "]"
        var filter = "{\"kinds\":[\(liveKind)],\"#t\":\(t),\"limit\":\(limit)"
        if let since { filter += ",\"since\":\(since)" }
        filter += "}"
        return "[\"REQ\",\"\(escape(subID))\",\(filter)]"
    }

    public static func closeFrame(subID: String) -> String { "[\"CLOSE\",\"\(escape(subID))\"]" }

    // MARK: - Chunking de blocos grandes (mídia)

    /// Relays públicos limitam o tamanho de um evento (tipicamente 64–512 KB), então uma foto (bloco
    /// de centenas de KB a MB) NÃO cabe num único evento. A solução é fatiar o bloco em N eventos
    /// relay-safe, sob a MESMA `mailbox`, e remontar no destino. Texto/mídia pequena continua indo
    /// inteiro (content = bloco), retrocompatível com o EVENTO DE RELAY v1.
    ///
    /// ==================== CHUNK DE RELAY v1 — CONGELADO ====================
    ///   content de um chunk = "BHK1|" msgId "|" index "|" total "|" slice
    ///     msgId  = 16 hex (8 bytes aleatórios) — agrupa os chunks de UMA mensagem
    ///     index  = decimal 0-based;  total = número de chunks (decimal, ≥1)
    ///     slice  = pedaço contíguo do bloco "BLKH01E.…" (alfabeto base64url + '.', nunca '|')
    ///   remontagem = concatenar as slices em ordem de index → bloco original
    ///   um bloco que cabe num evento NÃO é fatiado (vai como content = bloco, v1)
    /// Mudar qualquer parte exige versão nova.
    /// =======================================================================
    static let chunkMagic = "BHK1"

    /// `true` se o `content` é um envelope de chunk (e não um bloco `BLKH01E.…` inteiro). Os prefixos
    /// não colidem: bloco começa com "BLKH01E.", chunk com "BHK1|".
    public static func isChunk(_ content: String) -> Bool { content.hasPrefix(chunkMagic + "|") }

    /// Fatia um bloco em envelopes de chunk relay-safe. `[]` se precisaria de mais de `maxChunks`
    /// (grande demais para o transporte ao vivo → o chamador cai no compartilhar manual, honesto).
    /// `msgId` é dado pelo chamador (aleatório em produção; fixo nos testes de vetor).
    public static func chunkize(block: String, msgId: String, maxSliceChars: Int, maxChunks: Int) -> [String] {
        let scalars = Array(block.unicodeScalars)               // bloco é ASCII → count == chars
        guard maxSliceChars > 0, !scalars.isEmpty else { return [] }
        let n = (scalars.count + maxSliceChars - 1) / maxSliceChars
        guard n >= 1, n <= maxChunks else { return [] }
        var out: [String] = []; out.reserveCapacity(n)
        var i = 0, idx = 0
        while i < scalars.count {
            let end = min(i + maxSliceChars, scalars.count)
            let slice = String(String.UnicodeScalarView(scalars[i..<end]))
            out.append("\(chunkMagic)|\(msgId)|\(idx)|\(n)|\(slice)")
            i = end; idx += 1
        }
        return out
    }

    /// Lê um envelope de chunk. `nil` se não for um chunk válido (prefixo, campos, msgId hex, faixas).
    public static func parseChunk(_ content: String) -> (msgId: String, index: Int, total: Int, slice: String)? {
        guard content.hasPrefix(chunkMagic + "|") else { return nil }
        let parts = content.split(separator: "|", maxSplits: 4, omittingEmptySubsequences: false)
        guard parts.count == 5,
              let index = Int(parts[2]), let total = Int(parts[3]),
              total >= 1, index >= 0, index < total else { return nil }
        let msgId = String(parts[1])
        guard msgId.count == 16, msgId.allSatisfy({ $0.isHexDigit }) else { return nil }
        let slice = String(parts[4])
        guard !slice.isEmpty else { return nil }
        return (msgId, index, total, slice)
    }

    /// Remonta blocos fatiados a partir dos `content` dos eventos de chunk. Com LIMITES de memória
    /// (mensagens parciais simultâneas, chunks por mensagem, bytes por mensagem): entrada hostil/lossy
    /// não cresce sem teto. Mensagens parciais abandonadas são despejadas por ordem de chegada (FIFO)
    /// quando estoura o teto de simultâneas — cobre o caso de chunk que nunca completa.
    public struct ChunkReassembler {
        public let maxMessages: Int
        public let maxChunksPerMessage: Int
        public let maxTotalBytes: Int

        private struct Partial { var total: Int; var slices: [Int: String]; var bytes: Int }
        private var partial: [String: Partial] = [:]
        private var order: [String] = []

        public init(maxMessages: Int = 8, maxChunksPerMessage: Int = 64, maxTotalBytes: Int = 8 * 1024 * 1024) {
            self.maxMessages = maxMessages
            self.maxChunksPerMessage = maxChunksPerMessage
            self.maxTotalBytes = maxTotalBytes
        }

        /// Aceita o `content` de UM evento de chunk. Devolve o bloco completo quando a última fatia
        /// fecha a mensagem; `nil` enquanto falta pedaço (ou se não for chunk/exceder limites).
        public mutating func accept(_ content: String) -> String? {
            guard let c = Nostr.parseChunk(content), c.total <= maxChunksPerMessage else { return nil }
            if partial[c.msgId] == nil {
                if partial.count >= maxMessages, let oldest = order.first { drop(oldest) }
                partial[c.msgId] = Partial(total: c.total, slices: [:], bytes: 0)
                order.append(c.msgId)
            }
            guard var p = partial[c.msgId] else { return nil }
            guard p.total == c.total else { drop(c.msgId); return nil }   // total incoerente → descarta
            if p.slices[c.index] == nil {
                p.bytes += c.slice.utf8.count
                p.slices[c.index] = c.slice
            }
            guard p.bytes <= maxTotalBytes else { drop(c.msgId); return nil }
            partial[c.msgId] = p
            guard p.slices.count == p.total else { return nil }
            var block = ""; block.reserveCapacity(p.bytes)
            for i in 0..<p.total { guard let s = p.slices[i] else { return nil }; block += s }
            drop(c.msgId)
            return block
        }

        public mutating func reset() { partial = [:]; order = [] }

        private mutating func drop(_ id: String) {
            partial[id] = nil
            if let i = order.firstIndex(of: id) { order.remove(at: i) }
        }
    }

    // MARK: - Parse de quadros recebidos

    public enum Frame: Equatable {
        case event(sub: String, id: String, content: String)
        case eose(sub: String)
        case ok(id: String, accepted: Bool)
        case notice(String)
        case other
    }

    /// Lê um quadro do relay. Usa `JSONSerialization` (entrada arbitrária/hostil). `nil` = não é um
    /// quadro JSON válido.
    public static func parseFrame(_ text: String) -> Frame? {
        guard let data = text.data(using: .utf8),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [Any],
              let type = arr.first as? String else { return nil }
        switch type {
        case "EVENT":
            guard arr.count >= 3, let sub = arr[1] as? String,
                  let ev = arr[2] as? [String: Any],
                  let id = ev["id"] as? String, let content = ev["content"] as? String else { return .other }
            return .event(sub: sub, id: id, content: content)
        case "EOSE":
            guard arr.count >= 2, let sub = arr[1] as? String else { return .other }
            return .eose(sub: sub)
        case "OK":
            guard arr.count >= 3, let id = arr[1] as? String, let ok = arr[2] as? Bool else { return .other }
            return .ok(id: id, accepted: ok)
        case "NOTICE":
            return .notice((arr.count >= 2 ? arr[1] as? String : nil) ?? "")
        default:
            return .other
        }
    }

    // MARK: - Verificação (defesa em profundidade / testes; o relay já valida)

    static func verify(id: String, pubkeyHex: String, sigHex: String) -> Bool {
        guard let idBytes = bytes(id), idBytes.count == 32,
              let pk = bytes(pubkeyHex), let sig = bytes(sigHex),
              let xonly = try? P256K.Schnorr.XonlyKey(dataRepresentation: pk),
              let signature = try? P256K.Schnorr.SchnorrSignature(dataRepresentation: sig) else { return false }
        var msg = idBytes
        return xonly.isValid(signature, for: &msg)
    }

    // MARK: - Helpers

    /// Escape de string JSON no conjunto do NIP-01 (não escapa `/` nem não-ASCII; sem espaços).
    static func escape(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if u.value < 0x20 { out += String(format: "\\u%04x", u.value) }
                else { out.unicodeScalars.append(u) }
            }
        }
        return out
    }

    static func tagsJSON(_ tags: [[String]]) -> String {
        "[" + tags.map { tag in
            "[" + tag.map { "\"\(escape($0))\"" }.joined(separator: ",") + "]"
        }.joined(separator: ",") + "]"
    }

    static func hex(_ d: Data) -> String {
        let table = Array("0123456789abcdef")
        var s = String(); s.reserveCapacity(d.count * 2)
        for b in d { s.append(table[Int(b >> 4)]); s.append(table[Int(b & 0x0F)]) }
        return s
    }

    static func bytes(_ hexStr: String) -> [UInt8]? {
        guard hexStr.count % 2 == 0 else { return nil }
        var out = [UInt8](); out.reserveCapacity(hexStr.count / 2)
        var i = hexStr.startIndex
        while i < hexStr.endIndex {
            let j = hexStr.index(i, offsetBy: 2)
            guard let b = UInt8(hexStr[i..<j], radix: 16) else { return nil }
            out.append(b); i = j
        }
        return out
    }
}
