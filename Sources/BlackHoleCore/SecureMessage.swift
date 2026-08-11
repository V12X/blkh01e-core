import Foundation
import CryptoKit

public enum MessageError: Error, Equatable {
    case malformed              // não é um bloco BLKH01E válido / parse falhou / entrada abusiva
    case unsupportedVersion     // versão ou modo desconhecido
    case wrongPasswordOrCorrupt // AEAD falhou (senha errada ou adulteração)
    case emptyPassword
}

/// Gera e lê blocos de texto cifrado compartilháveis por qualquer canal (WhatsApp, AirDrop, etc.).
///
/// ========================= FORMATO DE FIO v1 — CONGELADO =========================
/// `BLKH01E.<versão>.<base64url(payload)>`  (linha única, robusto a copiar/colar)
///   payload   = header || AEAD(ChaCha20-Poly1305)
///   header    = magic "BH01"(4) | version(1) | mode(1) | opsLimit(u32 BE) | memLimit(u32 BE) | salt(16)   [30 bytes]
///   AAD       = o header inteiro (autentica versão/modo/params → fecha downgrade e adulteração)
///   plaintext cifrado = PAD( [u32 BE tamanhoReal] || textoClaro || zeros )  arredondado p/ múltiplo de 256
///                       (o padding esconde o comprimento da mensagem; fica DENTRO do AEAD)
/// v1 = MODO SENHA (Argon2id → ChaCha20-Poly1305). Já é resistente a quântico (cripto simétrica).
/// Extensão futura SEM quebrar v1: mode 2 = X25519, mode 3 = X-Wing (PQ). Roteamento usa SOMENTE o
/// header autenticado; o rótulo externo `.<versão>.` é conferido contra a versão autenticada.
/// QUALQUER mudança neste layout exige um novo `version`/`mode` — este é o contrato fixo.
/// ===============================================================================
public enum SecureMessage {
    private static let magic = Data("BH01".utf8)          // 4 bytes
    private static let version1: UInt8 = 1
    private static let modePassword: UInt8 = 1
    private static let modeX25519: UInt8 = 2              // mode 2: chave pública (autentica remetente)
    private static let headerLen = 4 + 1 + 1 + 4 + 4 + 16 // magic|ver|mode|ops|mem|salt = 30 (mode 1)
    private static let headerLenX = 4 + 1 + 1             // magic|ver|mode = 6 (mode 2; nada mais em claro)
    private static let x25519Salt = Data("BLKH01E/x25519-v1".utf8)   // domain-separator do HKDF
    private static let sealedMin = 12 + 16                // combined = nonce(12) || ct || tag(16)
    private static let padBlock = 256                     // granularidade do padding anti-metadado

    // Tetos anti-DoS na captura de volta (o bloco vem de canal hostil).
    private static let maxArmoredBytes = 2_000_000
    private static let maxTokenBytes = 1_048_576

    // MARK: - Encriptar (modo senha)

    public static func encrypt(_ plaintext: Data, password: String) throws -> String {
        try encrypt(plaintext, password: password, params: .standard())
    }

    /// Interno: parâmetros de KDF arbitrários (testes usam rápidos). A API pública fixa `.standard()`.
    static func encrypt(_ plaintext: Data, password: String, params: KDFParams) throws -> String {
        guard !password.isEmpty else { throw MessageError.emptyPassword }
        let salt = try KeyDerivation.newSalt()
        let key = try KeyDerivation.deriveKey(password: password, salt: salt, params: params)

        var header = Data(capacity: headerLen)
        header.append(magic)
        header.append(version1)
        header.append(modePassword)
        appendU32(&header, UInt32(params.opsLimit))
        appendU32(&header, UInt32(params.memLimit))
        header.append(contentsOf: salt)

        let sealed = try AEAD.seal(pad(plaintext), key: key, aad: header)   // padding DENTRO do AEAD
        return "BLKH01E.\(version1).\(base64urlEncode(header + sealed))"
    }

    // MARK: - Decifrar

    public static func decrypt(_ armored: String, password: String) throws -> Data {
        guard let (outerVersion, payload) = extractParts(armored) else { throw MessageError.malformed }
        guard payload.count >= headerLen + sealedMin else { throw MessageError.malformed }
        guard payload.subdata(in: 0..<4) == magic else { throw MessageError.malformed }

        let innerVersion = payload[4]
        guard outerVersion == String(innerVersion) else { throw MessageError.malformed }
        guard innerVersion == version1 else { throw MessageError.unsupportedVersion }
        guard payload[5] == modePassword else { throw MessageError.unsupportedVersion }

        let ops = Int(readU32(payload.subdata(in: 6..<10)))
        let mem = Int(readU32(payload.subdata(in: 10..<14)))
        let salt = Array(payload.subdata(in: 14..<30))
        let params = KDFParams(opsLimit: ops, memLimit: mem, algorithm: 1)
        // Anti-DoS (crash-on-open): o custo vem do header do atacante; o único produtor é o app
        // (sempre .standard()), então TETAMOS em .standard() — nada de forçar 1 GiB de Argon2id.
        let std = KDFParams.standard()
        guard params.withinSaneBounds(),
              params.opsLimit <= std.opsLimit,
              params.memLimit <= std.memLimit else { throw MessageError.malformed }
        guard !password.isEmpty else { throw MessageError.wrongPasswordOrCorrupt }

        let header = payload.subdata(in: 0..<headerLen)
        let sealed = payload.subdata(in: headerLen..<payload.count)
        guard let key = try? KeyDerivation.deriveKey(password: password, salt: salt, params: params),
              let padded = AEAD.open(sealed, key: key, aad: header),
              let plaintext = unpad(padded) else {
            throw MessageError.wrongPasswordOrCorrupt
        }
        return plaintext
    }

    // MARK: - Modo X25519 (mode 2) — autentica o remetente, sem senha

    /// Gera um par de identidade X25519 (Curve25519). `privateKey`/`publicKey` = 32 bytes crus.
    /// A pública é o que se troca por QR presencial; a privada vive sob a MK.
    public static func generateIdentity() -> (privateKey: Data, publicKey: Data) {
        let sk = Curve25519.KeyAgreement.PrivateKey()
        return (sk.rawRepresentation, sk.publicKey.rawRepresentation)
    }

    /// Chave simétrica derivada do ECDH (X25519) + HKDF, com o header como `sharedInfo` (amarra
    /// versão/modo). Simétrica: `ECDH(a_sk, b_pk) == ECDH(b_sk, a_pk)`.
    private static func sharedKey(myPrivateKey: Data, theirPublicKey: Data, header: Data) throws -> SymmetricKey {
        let sk = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: myPrivateKey)
        let pk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirPublicKey)
        let shared = try sk.sharedSecretFromKeyAgreement(with: pk)
        return shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: x25519Salt,
                                              sharedInfo: header, outputByteCount: 32)
    }

    /// Cifra para a chave pública do destinatário, autenticando via a chave privada do remetente.
    /// A pública do remetente NÃO viaja no bloco (privacidade): quem recebe descobre o remetente
    /// tentando as chaves dos seus contatos (`decrypt(_:recipientPrivateKey:senderCandidates:)`).
    public static func encrypt(_ plaintext: Data, toPublicKey recipientPK: Data,
                               senderPrivateKey: Data) throws -> String {
        guard recipientPK.count == 32, senderPrivateKey.count == 32 else { throw MessageError.malformed }
        var header = Data(capacity: headerLenX)
        header.append(magic); header.append(version1); header.append(modeX25519)
        guard let key = try? sharedKey(myPrivateKey: senderPrivateKey, theirPublicKey: recipientPK, header: header)
        else { throw MessageError.malformed }
        let sealed = try AEAD.seal(pad(plaintext), key: key, aad: header)
        return "BLKH01E.\(version1).\(base64urlEncode(header + sealed))"
    }

    /// Decifra um bloco mode 2 com a chave privada do destinatário. Tenta cada chave pública
    /// candidata (dos contatos); a que abrir É o remetente autenticado (o AEAD só cede com o
    /// segredo ECDH certo). Devolve o texto e a pública do remetente.
    public static func decrypt(_ armored: String, recipientPrivateKey: Data,
                               senderCandidates: [Data]) throws -> (plaintext: Data, senderPublicKey: Data) {
        guard recipientPrivateKey.count == 32 else { throw MessageError.malformed }
        guard let (outerVersion, payload) = extractParts(armored) else { throw MessageError.malformed }
        guard payload.count >= headerLenX + sealedMin else { throw MessageError.malformed }
        guard payload.subdata(in: 0..<4) == magic else { throw MessageError.malformed }
        let innerVersion = payload[4]
        guard outerVersion == String(innerVersion) else { throw MessageError.malformed }
        guard innerVersion == version1 else { throw MessageError.unsupportedVersion }
        guard payload[5] == modeX25519 else { throw MessageError.unsupportedVersion }

        let header = payload.subdata(in: 0..<headerLenX)
        let sealed = payload.subdata(in: headerLenX..<payload.count)
        for candidate in senderCandidates where candidate.count == 32 {
            guard let key = try? sharedKey(myPrivateKey: recipientPrivateKey, theirPublicKey: candidate, header: header),
                  let padded = AEAD.open(sealed, key: key, aad: header),
                  let plaintext = unpad(padded) else { continue }
            return (plaintext, candidate)
        }
        throw MessageError.wrongPasswordOrCorrupt
    }

    /// Modo do bloco (1 = senha, 2 = X25519), ou `nil` se não for um bloco válido. A UI usa para
    /// rotear: pedir senha (1) ou usar as chaves (2).
    public static func mode(of armored: String) -> Int? {
        guard let (_, payload) = extractParts(armored) else { return nil }
        guard payload.count >= 6, payload.subdata(in: 0..<4) == magic else { return nil }
        return Int(payload[5])
    }

    // MARK: - Detecção / extração (captura de volta)

    public static func isMessage(_ text: String) -> Bool { extractToken(from: text) != nil }

    public static func extractToken(from text: String) -> String? {
        guard text.utf8.count <= maxArmoredBytes else { return nil }
        let pattern = "BLKH01E\\.[0-9]+\\.[A-Za-z0-9_-]+"
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        let ns = text as NSString
        guard let m = re.firstMatch(in: text, range: NSRange(location: 0, length: ns.length)) else { return nil }
        let token = ns.substring(with: m.range)
        guard token.utf8.count <= maxTokenBytes else { return nil }
        return token
    }

    // MARK: - Padding anti-metadado

    /// `[u32 BE tamanhoReal] || textoClaro || zeros`, arredondado ao próximo múltiplo de `padBlock`.
    /// Fica dentro do AEAD, então o padding é indistinguível no ciphertext; o tamanho do bloco só
    /// revela o comprimento ARREDONDADO (256, 512, …), não o exato.
    private static func pad(_ plaintext: Data) -> Data {
        var body = Data(capacity: 4 + plaintext.count)
        appendU32(&body, UInt32(truncatingIfNeeded: plaintext.count))
        body.append(plaintext)
        let target = ((body.count + padBlock - 1) / padBlock) * padBlock
        if body.count < target { body.append(Data(count: target - body.count)) }
        return body
    }

    private static func unpad(_ padded: Data) -> Data? {
        guard padded.count >= 4 else { return nil }
        let len = Int(readU32(padded.subdata(in: 0..<4)))
        guard len >= 0, 4 + len <= padded.count else { return nil }
        return padded.subdata(in: 4..<(4 + len))
    }

    // MARK: - Helpers

    private static func extractParts(_ armored: String) -> (outerVersion: String, payload: Data)? {
        guard let token = extractToken(from: armored) else { return nil }
        let parts = token.split(separator: ".")
        guard parts.count == 3, let payload = base64urlDecode(String(parts[2])) else { return nil }
        return (String(parts[1]), payload)
    }

    private static func appendU32(_ d: inout Data, _ v: UInt32) {
        var be = v.bigEndian
        withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
    }
    private static func readU32(_ d: Data) -> UInt32 {
        d.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian
    }
    private static func base64urlEncode(_ d: Data) -> String {
        d.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    private static func base64urlDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        return Data(base64Encoded: b)
    }
}
