import Foundation

/// Metadado recuperado de um arquivo cifrado. `name == nil` = arquivo LEGADO (sem envelope): os
/// bytes são o conteúdo cru (uma imagem, do fluxo antigo `.blkhimg`).
public struct DecodedFile: Equatable {
    public let name: String?
    public let uti: String?
    public let data: Data
    public init(name: String?, uti: String?, data: Data) {
        self.name = name; self.uti = uti; self.data = data
    }
    /// Sem nome declarado = fluxo antigo, que só carregava imagem crua.
    public var isLegacy: Bool { name == nil }
}

/// Envelope interno que embrulha o conteúdo com NOME + TIPO (UTI) ANTES de cifrar com `SecureFile`.
/// Assim um arquivo cifrado sabe se abriu um áudio, um PDF ou uma imagem — sem isso o destinatário
/// só conseguiria adivinhar pelo conteúdo. O envelope vai DENTRO do texto claro do `SecureFile` (o
/// formato de fio dele segue CONGELADO); logo é cifrado junto e o nome do arquivo NÃO vaza.
///
/// ==================== ENVELOPE v1 ====================
///   magic "BHE1"(4) | version(1)=1 | nameLen(u16 BE) | name(UTF8) | utiLen(u16 BE) | uti(UTF8) | data
/// =====================================================
/// Retrocompat: `unwrap` de bytes SEM o magic devolve `DecodedFile(name: nil, ...)` — os `.blkhimg`
/// antigos (imagem crua, sem envelope) seguem abrindo. Nenhum arquivo de imagem real começa com
/// "BHE1", e o texto claro já é autenticado pelo AEAD do `SecureFile` (o envelope não abre brecha).
public enum FileEnvelope {
    private static let magic: [UInt8] = Array("BHE1".utf8)
    private static let version1: UInt8 = 1
    /// Nome/UTI sãos: acima disso o escritor trunca e o leitor recusa (trata como legado). Impede
    /// que um comprimento mentiroso num arquivo hostil vire alocação absurda.
    private static let maxFieldLen = 1024

    public static func wrap(_ data: Data, name: String, uti: String?) -> Data {
        let nameBytes = Array(name.utf8.prefix(maxFieldLen))
        let utiBytes = Array((uti ?? "").utf8.prefix(maxFieldLen))
        var out = Data(capacity: magic.count + 1 + 2 + nameBytes.count + 2 + utiBytes.count + data.count)
        out.append(contentsOf: magic)
        out.append(version1)
        appendU16(&out, UInt16(nameBytes.count))
        out.append(contentsOf: nameBytes)
        appendU16(&out, UInt16(utiBytes.count))
        out.append(contentsOf: utiBytes)
        out.append(data)
        return out
    }

    public static func unwrap(_ plaintext: Data) -> DecodedFile {
        let b = [UInt8](plaintext)
        guard b.count >= magic.count + 1 + 2,
              Array(b[0..<magic.count]) == magic,
              b[magic.count] == version1 else {
            return legacy(plaintext)               // não é envelope: bytes crus (imagem antiga)
        }
        var i = magic.count + 1
        guard let nameLen = readU16(b, i) else { return legacy(plaintext) }
        i += 2
        guard nameLen <= maxFieldLen, i + Int(nameLen) + 2 <= b.count else { return legacy(plaintext) }
        let name = String(decoding: b[i..<i + Int(nameLen)], as: UTF8.self)
        i += Int(nameLen)
        guard let utiLen = readU16(b, i) else { return legacy(plaintext) }
        i += 2
        guard utiLen <= maxFieldLen, i + Int(utiLen) <= b.count else { return legacy(plaintext) }
        let uti = String(decoding: b[i..<i + Int(utiLen)], as: UTF8.self)
        i += Int(utiLen)
        let data = Data(b[i..<b.count])
        return DecodedFile(name: name, uti: uti.isEmpty ? nil : uti, data: data)
    }

    // MARK: - Helpers

    private static func legacy(_ d: Data) -> DecodedFile { DecodedFile(name: nil, uti: nil, data: d) }

    private static func appendU16(_ d: inout Data, _ v: UInt16) {
        d.append(UInt8(v >> 8)); d.append(UInt8(v & 0xFF))
    }
    private static func readU16(_ b: [UInt8], _ i: Int) -> UInt16? {
        guard i + 2 <= b.count else { return nil }
        return (UInt16(b[i]) << 8) | UInt16(b[i + 1])
    }
}
