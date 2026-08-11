import Foundation
import CryptoKit

public enum RatchetError: Error, Equatable {
    case malformed              // não é um bloco de ratchet válido / parse falhou / entrada abusiva
    case unsupportedVersion
    case undecryptable          // AEAD falhou (chave errada / adulteração / fora de sincronia)
    case notReady               // o RESPONDEDOR ainda não recebeu a 1ª mensagem, não pode enviar
    case skipLimitExceeded      // gap de mensagens fora de ordem além do teto (anti-DoS)
}

/// Estado de uma SESSÃO Double Ratchet com um contato. Opaco para o app — é só guardado cifrado no
/// cofre (Codable) e passado de volta em cada `encrypt`/`decrypt`. Contém material de chave sensível;
/// vive apenas sob a MK como qualquer outro conteúdo.
public struct RatchetState: Codable, Equatable {
    var rootKey: Data           // RK — chave-raiz da cadeia
    var dhSelfPriv: Data        // DHs — nosso par de ratchet atual
    var dhSelfPub: Data
    var dhRemote: Data?         // DHr — pública de ratchet do outro (nil no responder até o 1º recv)
    var sendCK: Data?           // CKs — chain key de envio (nil no responder até o 1º recv)
    var recvCK: Data?           // CKr — chain key de recepção
    var sendN: UInt32           // Ns — nº de mensagens já enviadas na cadeia atual
    var recvN: UInt32           // Nr — nº de mensagens já recebidas na cadeia atual
    var prevN: UInt32           // PN — nº de mensagens da cadeia de envio ANTERIOR
    var skipped: [SkippedKey]   // chaves de mensagens puladas (fora de ordem), com teto
}

/// Chave de mensagem guardada para uma mensagem que ainda não chegou (fora de ordem). Identificada
/// pela pública de ratchet da cadeia + o índice.
public struct SkippedKey: Codable, Equatable {
    var dhPub: Data
    var n: UInt32
    var mk: Data
}

/// Double Ratchet (à la Signal) SEM servidor: dá forward secrecy + recuperação pós-comprometimento
/// às mensagens por contato. O bootstrap sai do QR presencial já existente (as chaves de identidade
/// X25519). O transporte segue livre — cada mensagem vira um bloco `BLKH01E.…` que você manda por
/// qualquer canal. Construído sobre as MESMAS primitivas auditadas do resto do app (X25519, HKDF-
/// SHA256, HMAC-SHA256, ChaCha20-Poly1305); a lógica de estado segue a especificação pública.
///
/// ==================== FORMATO DE FIO v1 — CONGELADO ====================
/// `BLKH01E.<versão>.<base64url(payload)>`  (linha única, robusto a copiar/colar)
///   payload = header || AEAD(ChaCha20-Poly1305)
///   header  = magic "BHR1"(4) | version(1) | dhPub(32) | PN(u32 BE) | N(u32 BE)   [45 bytes]
///   AAD     = o header inteiro (autentica a pública de ratchet e os contadores)
///   plaintext cifrado = PAD([u32 tamanhoReal] || claro || zeros) múltiplo de 256 (anti-metadado)
/// O magic `BHR1` distingue do `SecureMessage` (`BH01`); o roteamento usa `isRatchetMessage`.
/// Qualquer mudança neste layout exige `version` novo.
/// ======================================================================
public enum DoubleRatchet {
    private static let magic = Data("BHR1".utf8)
    private static let version1: UInt8 = 1
    private static let headerLen = 4 + 1 + 32 + 4 + 4       // 45
    private static let sealedMin = 12 + 16                  // nonce(12) || ct || tag(16)
    private static let padBlock = 256
    private static let maxSkip = 100                        // teto de mensagens fora de ordem (escopo A)
    private static let maxArmoredBytes = 2_000_000

    // Separadores de domínio do HKDF (nunca reusar entre propósitos).
    private static let skSalt = Data("BLKH01E/ratchet-sk-v1".utf8)
    private static let rkInfo = Data("BLKH01E/ratchet-rk-v1".utf8)

    // MARK: - Bootstrap (a partir das chaves de identidade do QR)

    /// Inicia a sessão a partir da SUA identidade X25519 e da pública do contato (já trocadas por QR).
    /// Papel determinístico: a pública lexicograficamente MAIOR é a INICIADORA (pode enviar primeiro);
    /// a menor é a RESPONDEDORA (precisa receber a 1ª mensagem antes de enviar). Assim os dois lados
    /// derivam a mesma raiz sem mensagem extra de handshake.
    public static func initialize(identityPrivateKey: Data, identityPublicKey: Data,
                                  peerIdentityPublicKey: Data) throws -> RatchetState {
        guard identityPrivateKey.count == 32, identityPublicKey.count == 32,
              peerIdentityPublicKey.count == 32 else { throw RatchetError.malformed }
        guard identityPublicKey != peerIdentityPublicKey else { throw RatchetError.malformed }

        let sharedDH = try dh(identityPrivateKey, peerIdentityPublicKey)
        let pairInfo = lexLess(identityPublicKey, peerIdentityPublicKey)
            ? identityPublicKey + peerIdentityPublicKey
            : peerIdentityPublicKey + identityPublicKey
        let sk = hkdf(ikm: sharedDH, salt: skSalt, info: pairInfo, outputByteCount: 32)

        let isInitiator = lexLess(peerIdentityPublicKey, identityPublicKey)   // eu > par → iniciador
        if isInitiator {
            // "Alice": gera DHs fresco, DHr = identidade do par, (RK, CKs) = KDF_RK(SK, DH(DHs, DHr)).
            let (priv, pub) = generateDH()
            let (rk, cks) = kdfRK(rk: sk, dhOut: try dh(priv, peerIdentityPublicKey))
            return RatchetState(rootKey: rk, dhSelfPriv: priv, dhSelfPub: pub,
                                dhRemote: peerIdentityPublicKey, sendCK: cks, recvCK: nil,
                                sendN: 0, recvN: 0, prevN: 0, skipped: [])
        } else {
            // "Bob": DHs = a própria identidade, RK = SK, sem cadeias ainda (surgem no 1º recv).
            return RatchetState(rootKey: sk, dhSelfPriv: identityPrivateKey, dhSelfPub: identityPublicKey,
                                dhRemote: nil, sendCK: nil, recvCK: nil,
                                sendN: 0, recvN: 0, prevN: 0, skipped: [])
        }
    }

    // MARK: - Encriptar

    /// Cifra a próxima mensagem, avançando a cadeia de envio (forward secrecy). Devolve o bloco
    /// `BLKH01E.…`. Lança `.notReady` se você é o responder e ainda não recebeu a 1ª mensagem.
    public static func encrypt(_ plaintext: Data, state: inout RatchetState) throws -> String {
        var st = state
        guard let cks = st.sendCK else { throw RatchetError.notReady }
        let (mk, nextCK) = kdfCK(cks)
        let header = makeHeader(dhPub: st.dhSelfPub, pn: st.prevN, n: st.sendN)
        let sealed = try AEAD.seal(pad(plaintext), key: SymmetricKey(data: mk), aad: header)
        st.sendCK = nextCK
        st.sendN += 1
        state = st
        return "BLKH01E.\(version1).\(base64urlEncode(header + sealed))"
    }

    // MARK: - Decifrar

    /// Decifra um bloco, avançando o estado. O estado SÓ é comitado se a decifragem der certo — um
    /// bloco forjado/corrompido não dessincroniza a sessão. Lida com fora de ordem (chaves puladas)
    /// e com o passo DH-ratchet quando uma pública de ratchet nova aparece.
    public static func decrypt(_ armored: String, state: inout RatchetState) throws -> Data {
        let msg = try parse(armored)
        var st = state

        // 1) Já veio uma chave pulada para esta (cadeia, índice)? (mensagem fora de ordem que chegou depois)
        if let idx = st.skipped.firstIndex(where: { $0.dhPub == msg.dhPub && $0.n == msg.n }) {
            guard let pt = open(msg.sealed, mk: st.skipped[idx].mk, aad: msg.header) else {
                throw RatchetError.undecryptable
            }
            st.skipped.remove(at: idx)
            state = st
            return pt
        }

        // 2) Pública de ratchet nova → pula o resto da cadeia atual e faz o passo DH.
        if st.dhRemote == nil || msg.dhPub != st.dhRemote! {
            try skipMessageKeys(&st, until: msg.pn)
            try dhRatchet(&st, newRemote: msg.dhPub)
        }
        // 3) Pula até o índice desta mensagem na cadeia (guardando as chaves puladas).
        try skipMessageKeys(&st, until: msg.n)
        // 4) Deriva a chave desta mensagem e abre. Comita só no sucesso.
        guard let ckr = st.recvCK else { throw RatchetError.undecryptable }
        let (mk, nextCK) = kdfCK(ckr)
        guard let pt = open(msg.sealed, mk: mk, aad: msg.header) else { throw RatchetError.undecryptable }
        st.recvCK = nextCK
        st.recvN += 1
        state = st
        return pt
    }

    /// É um bloco de ratchet (magic `BHR1`)? Usado pelo app para rotear entre ratchet / SecureMessage.
    public static func isRatchetMessage(_ text: String) -> Bool {
        guard let payload = extractPayload(text), payload.count >= 5 else { return false }
        return payload.subdata(in: 0..<4) == magic
    }

    // MARK: - Passos internos do ratchet

    /// Pula (deriva e guarda) as chaves de mensagem da cadeia de recepção até `until`, para as
    /// mensagens que ainda não chegaram. Teto anti-DoS: um gap único acima de `maxSkip` é recusado.
    private static func skipMessageKeys(_ st: inout RatchetState, until: UInt32) throws {
        guard until > st.recvN else { return }              // nada a pular (ou já passamos)
        guard until - st.recvN <= UInt32(maxSkip) else { throw RatchetError.skipLimitExceeded }
        guard var ck = st.recvCK else {                     // sem cadeia de recepção ainda
            if until > st.recvN { throw RatchetError.undecryptable }
            return
        }
        let chain = st.dhRemote ?? Data()
        while st.recvN < until {
            let (mk, next) = kdfCK(ck)
            st.skipped.append(SkippedKey(dhPub: chain, n: st.recvN, mk: mk))
            ck = next
            st.recvN += 1
        }
        st.recvCK = ck
        if st.skipped.count > maxSkip { st.skipped.removeFirst(st.skipped.count - maxSkip) }  // FIFO
    }

    /// Passo DH-ratchet: gira a raiz com a pública nova do outro, deriva a cadeia de recepção nova,
    /// gera nosso par de ratchet novo e deriva a cadeia de envio nova. É o que dá recuperação pós-
    /// comprometimento.
    private static func dhRatchet(_ st: inout RatchetState, newRemote: Data) throws {
        st.prevN = st.sendN
        st.sendN = 0
        st.recvN = 0
        st.dhRemote = newRemote
        let (rk1, ckr) = kdfRK(rk: st.rootKey, dhOut: try dh(st.dhSelfPriv, newRemote))
        st.rootKey = rk1
        st.recvCK = ckr
        let (priv, pub) = generateDH()
        st.dhSelfPriv = priv
        st.dhSelfPub = pub
        let (rk2, cks) = kdfRK(rk: st.rootKey, dhOut: try dh(priv, newRemote))
        st.rootKey = rk2
        st.sendCK = cks
    }

    // MARK: - KDFs (sobre HKDF/HMAC-SHA256)

    /// KDF da raiz: (novaRK, chainKey) = HKDF(salt = RK, ikm = saída-DH). 64 bytes → 32 + 32.
    private static func kdfRK(rk: Data, dhOut: Data) -> (rk: Data, ck: Data) {
        let out = hkdf(ikm: dhOut, salt: rk, info: rkInfo, outputByteCount: 64)
        return (out.subdata(in: 0..<32), out.subdata(in: 32..<64))
    }

    /// KDF da cadeia: chave-de-mensagem = HMAC(CK, 0x01); próxima CK = HMAC(CK, 0x02).
    private static func kdfCK(_ ck: Data) -> (mk: Data, next: Data) {
        let key = SymmetricKey(data: ck)
        let mk = Data(HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: key))
        let next = Data(HMAC<SHA256>.authenticationCode(for: Data([0x02]), using: key))
        return (mk, next)
    }

    private static func hkdf(ikm: Data, salt: Data, info: Data, outputByteCount: Int) -> Data {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info,
                               outputByteCount: outputByteCount).withUnsafeBytes { Data($0) }
    }

    private static func dh(_ sk: Data, _ pk: Data) throws -> Data {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pk)
        return try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
    }

    private static func generateDH() -> (priv: Data, pub: Data) {
        let sk = Curve25519.KeyAgreement.PrivateKey()
        return (sk.rawRepresentation, sk.publicKey.rawRepresentation)
    }

    // MARK: - Wire (header/parse/armor) e AEAD

    private static func makeHeader(dhPub: Data, pn: UInt32, n: UInt32) -> Data {
        var h = Data(capacity: headerLen)
        h.append(magic); h.append(version1); h.append(dhPub)
        appendU32(&h, pn); appendU32(&h, n)
        return h
    }

    private struct ParsedMsg { let dhPub: Data; let pn: UInt32; let n: UInt32; let header: Data; let sealed: Data }

    private static func parse(_ armored: String) throws -> ParsedMsg {
        guard let payload = extractPayload(armored) else { throw RatchetError.malformed }
        guard payload.count >= headerLen + sealedMin else { throw RatchetError.malformed }
        guard payload.subdata(in: 0..<4) == magic else { throw RatchetError.malformed }
        guard payload[4] == version1 else { throw RatchetError.unsupportedVersion }
        let dhPub = payload.subdata(in: 5..<37)
        let pn = readU32(payload.subdata(in: 37..<41))
        let n = readU32(payload.subdata(in: 41..<45))
        let header = payload.subdata(in: 0..<headerLen)
        let sealed = payload.subdata(in: headerLen..<payload.count)
        return ParsedMsg(dhPub: dhPub, pn: pn, n: n, header: header, sealed: sealed)
    }

    private static func open(_ sealed: Data, mk: Data, aad: Data) -> Data? {
        guard let padded = AEAD.open(sealed, key: SymmetricKey(data: mk), aad: aad) else { return nil }
        return unpad(padded)
    }

    private static func extractPayload(_ text: String) -> Data? {
        guard text.utf8.count <= maxArmoredBytes,
              let token = SecureMessage.extractToken(from: text) else { return nil }
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        return base64urlDecode(String(parts[2]))
    }

    // MARK: - Padding anti-metadado (idêntico ao SecureMessage: dentro do AEAD)

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

    // MARK: - Helpers de bytes

    private static func lexLess(_ a: Data, _ b: Data) -> Bool {
        for (x, y) in zip(a, b) where x != y { return x < y }
        return a.count < b.count
    }
    private static func appendU32(_ d: inout Data, _ v: UInt32) {
        var be = v.bigEndian
        withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
    }
    private static func readU32(_ d: Data) -> UInt32 {
        d.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian
    }
    private static func base64urlEncode(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    private static func base64urlDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        return Data(base64Encoded: b)
    }
}
