import Foundation
import CryptoKit

public enum SecureFileError: Error, Equatable {
    case malformed                  // não é um arquivo BHF1 válido / truncado
    case unsupportedVersion
    case wrongPasswordOrCorrupt     // AEAD falhou (senha errada ou adulteração) — erro ÚNICO
    case emptyPassword
    case tooLarge                   // acima do teto de RAM do v1
}

/// Arquivo cifrado de conteúdo binário (ex.: uma IMAGEM) para ENVIAR a alguém por qualquer canal
/// (WhatsApp/AirDrop). Análogo ao `SecureMessage`, mas binário e de payload único — imagem é grande
/// demais para colar como texto base64. O destinatário abre com a SENHA combinada (não precisa de
/// cofre). Reusa as mesmas primitivas auditadas: Argon2id (esticar a senha) + ChaCha20-Poly1305.
///
/// ================== FORMATO v1 — CONGELADO ==================
///   header = magic "BHF1"(4) | version(1) | reserved(1)=0 | opsLimit(u32 BE) | memLimit(u32 BE)
///            | salt(16)                                                        [30 bytes]
///   body   = AEAD(payload, key=Argon2id(senha, salt), aad=header)   ← nonce||ct||tag
/// AAD = header inteiro (fecha downgrade/adulteração). Qualquer mudança exige `version` novo.
/// ============================================================
///
/// SEM padding anti-metadado (ao contrário do `SecureMessage`): o tamanho de uma imagem já é revelado
/// pelo próprio tamanho do arquivo; acolchoar seria só desperdício. Teto honesto igual ao dos textos:
/// senha fraca + arquivo vazado = conteúdo aberto offline; só o Argon2id segura.
public enum SecureFile {
    private static let magic = Data("BHF1".utf8)
    private static let version1: UInt8 = 1
    private static let modePassword: UInt8 = 0              // byte 5: 0 = senha (o "reserved" do v1)
    private static let modeX25519: UInt8 = 2               // byte 5: 2 = X25519 (autentica remetente)
    private static let headerLen = 4 + 1 + 1 + 4 + 4 + 16   // 30 (modo senha)
    private static let headerLenX = 4 + 1 + 1               // 6 (modo X25519: nada mais em claro)
    private static let xSalt = Data("BLKH01E/securefile-x25519-v1".utf8)   // domain-separator do HKDF
    private static let sealedMin = 12 + 16                  // nonce(12) || ct || tag(16)

    /// Teto de RAM do v1 (monta inteiro em memória). Mesma faixa dos import de mídia. 200 MB cobre
    /// vídeos/arquivos grandes; o pico de RAM ao cifrar (~3× o arquivo) cabe folgado em aparelhos
    /// modernos (6–8 GB).
    public static let maxBytes = 200_000_000

    // MARK: - Cifrar

    public static func seal(_ payload: Data, password: String) throws -> Data {
        try seal(payload, password: password, params: .standard())
    }

    /// Interno: KDF arbitrário (testes usam rápido). A API pública fixa `.standard()`.
    static func seal(_ payload: Data, password: String, params: KDFParams) throws -> Data {
        guard !password.isEmpty else { throw SecureFileError.emptyPassword }
        guard payload.count <= maxBytes else { throw SecureFileError.tooLarge }
        let salt = try KeyDerivation.newSalt()
        let key = try KeyDerivation.deriveKey(password: password, salt: salt, params: params)

        var header = Data(capacity: headerLen)
        header.append(magic)
        header.append(version1)
        header.append(0)
        appendU32(&header, UInt32(params.opsLimit))
        appendU32(&header, UInt32(params.memLimit))
        header.append(contentsOf: salt)

        let sealed = try AEAD.seal(payload, key: key, aad: header)
        return header + sealed
    }

    // MARK: - Abrir

    public static func open(_ data: Data, password: String) throws -> Data {
        guard data.count >= headerLen + sealedMin else { throw SecureFileError.malformed }
        guard data.count <= maxBytes + headerLen + 100 else { throw SecureFileError.tooLarge }
        let header = data.subdata(in: 0..<headerLen)
        guard header.subdata(in: 0..<4) == magic else { throw SecureFileError.malformed }
        guard header[4] == version1 else { throw SecureFileError.unsupportedVersion }
        guard header[5] == modePassword else { throw SecureFileError.unsupportedVersion }   // modo 2 usa outro `open`

        let ops = Int(readU32(header.subdata(in: 6..<10)))
        let mem = Int(readU32(header.subdata(in: 10..<14)))
        let salt = Array(header.subdata(in: 14..<30))
        let params = KDFParams(opsLimit: ops, memLimit: mem, algorithm: 1)
        // Anti-DoS: params vêm de arquivo possivelmente hostil; o produtor legítimo usa `.standard()`,
        // então TETAMOS ali (mesma regra do SecureMessage/VaultArchive).
        let std = KDFParams.standard()
        guard params.withinSaneBounds(),
              params.opsLimit <= std.opsLimit,
              params.memLimit <= std.memLimit else { throw SecureFileError.malformed }
        guard !password.isEmpty else { throw SecureFileError.wrongPasswordOrCorrupt }

        let sealed = data.subdata(in: headerLen..<data.count)
        guard let key = try? KeyDerivation.deriveKey(password: password, salt: salt, params: params),
              let plaintext = AEAD.open(sealed, key: key, aad: header) else {
            throw SecureFileError.wrongPasswordOrCorrupt
        }
        return plaintext
    }

    // MARK: - Modo X25519 (byte 5 = 2) — cifra p/ um CONTATO, autenticando o remetente

    /// Modo do arquivo: 1 = senha, 2 = X25519, ou `nil` se não for um `.blkh` válido. A UI usa para
    /// rotear (pedir senha vs abrir com a identidade + contatos).
    public static func mode(of data: Data) -> Int? {
        guard data.count >= headerLenX, data.subdata(in: 0..<4) == magic, data[4] == version1 else { return nil }
        return data[5] == modeX25519 ? 2 : 1   // byte 5: 0 (reserved do v1) conta como senha
    }

    /// Cifra `payload` para a chave pública do destinatário, autenticando com a privada do remetente.
    /// A pública do remetente NÃO viaja (privacidade); quem recebe descobre tentando as chaves dos
    /// contatos. Sem senha, sem Argon2 (o segredo é o ECDH). Mesmo teto de RAM do modo senha.
    public static func seal(_ payload: Data, toPublicKey recipientPK: Data, senderPrivateKey: Data) throws -> Data {
        guard recipientPK.count == 32, senderPrivateKey.count == 32 else { throw SecureFileError.malformed }
        guard payload.count <= maxBytes else { throw SecureFileError.tooLarge }
        var header = Data(capacity: headerLenX)
        header.append(magic); header.append(version1); header.append(modeX25519)
        guard let key = try? xSharedKey(myPrivateKey: senderPrivateKey, theirPublicKey: recipientPK, header: header)
        else { throw SecureFileError.malformed }
        let sealed = try AEAD.seal(payload, key: key, aad: header)
        return header + sealed
    }

    /// Abre um arquivo modo 2 com a privada do destinatário, tentando cada pública candidata (dos
    /// contatos). A que abrir É o remetente autenticado. Devolve o payload e a pública do remetente.
    public static func open(_ data: Data, recipientPrivateKey: Data,
                            senderCandidates: [Data]) throws -> (payload: Data, senderPublicKey: Data) {
        guard recipientPrivateKey.count == 32 else { throw SecureFileError.malformed }
        guard data.count >= headerLenX + sealedMin else { throw SecureFileError.malformed }
        guard data.count <= maxBytes + headerLenX + 100 else { throw SecureFileError.tooLarge }
        guard data.subdata(in: 0..<4) == magic else { throw SecureFileError.malformed }
        guard data[4] == version1 else { throw SecureFileError.unsupportedVersion }
        guard data[5] == modeX25519 else { throw SecureFileError.unsupportedVersion }
        let header = data.subdata(in: 0..<headerLenX)
        let sealed = data.subdata(in: headerLenX..<data.count)
        for candidate in senderCandidates where candidate.count == 32 {
            guard let key = try? xSharedKey(myPrivateKey: recipientPrivateKey, theirPublicKey: candidate, header: header),
                  let payload = AEAD.open(sealed, key: key, aad: header) else { continue }
            return (payload, candidate)
        }
        throw SecureFileError.wrongPasswordOrCorrupt
    }

    /// Chave simétrica do ECDH (X25519) + HKDF, com o header como `sharedInfo`. Simétrica.
    private static func xSharedKey(myPrivateKey: Data, theirPublicKey: Data, header: Data) throws -> SymmetricKey {
        let sk = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: myPrivateKey)
        let pk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirPublicKey)
        let shared = try sk.sharedSecretFromKeyAgreement(with: pk)
        return shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: xSalt,
                                              sharedInfo: header, outputByteCount: 32)
    }

    // MARK: - Helpers

    private static func appendU32(_ d: inout Data, _ v: UInt32) {
        var be = v.bigEndian
        withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
    }
    private static func readU32(_ d: Data) -> UInt32 {
        d.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian
    }
}
