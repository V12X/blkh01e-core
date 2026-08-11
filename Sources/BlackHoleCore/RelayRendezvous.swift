import Foundation
import CryptoKit

/// Endereçamento da **sessão ao vivo** (transporte por relays públicos). NÃO toca a criptografia das
/// mensagens: o conteúdo continua sendo o bloco `BHR1` do Double Ratchet (formato congelado). Isto
/// aqui só decide EM QUE CAIXA-POSTAL pseudônima os dois lados se encontram no relay.
///
/// Os dois lados derivam a MESMA caixa a partir do segredo estável do par (ECDH das identidades
/// X25519), sem handshake — cada um calcula sozinho. A caixa ROTACIONA por dia (quebra correlação de
/// longo prazo) e tem SPLIT por direção (você publica numa caixa e assina a do outro, então nunca
/// recebe o eco das próprias mensagens).
///
/// TETO HONESTO (dito na UI): o relay/rede vê seu IP, o horário e o tamanho-arredondado, além da
/// `mailbox` do dia — NUNCA o conteúdo, a sua identidade nem quem é o par. A `mailbox` é derivada do
/// segredo do par, então não é descobrível por quem não tem esse segredo.
///
/// ==================== RENDEZVOUS v1 — CONGELADO ====================
///   segredoDoPar = X25519(minhaIdentidadePriv, identidadePubDoContato)   // 32 B, simétrico
///   dia          = floor(epochUTC / 86400)                               // u64
///   (lo, hi)     = ordem lexicográfica das DUAS identidades públicas
///   dirEnvio     = (minhaPub == hi) ? 0x01 : 0x00                        // "hi" publica em 0x01
///   mailbox(d)   = HKDF-SHA256(ikm=segredoDoPar, salt="BLKH01E/relay-rendezvous-v1",
///                              info = u64BE(dia) || byte(d), L=32)        // 32 B → hex minúsculo
///   PUBLICAR  = mailbox(dirEnvio) de HOJE
///   ASSINAR   = mailbox(1 - dirEnvio) de ONTEM, HOJE e AMANHÃ            // janela p/ fuso + buffer
/// Qualquer mudança neste layout exige uma versão nova (salt/`v2`).
/// ===================================================================
public enum RelayRendezvous {
    /// Separador de domínio do HKDF (também a etiqueta de versão do formato).
    static let salt = Data("BLKH01E/relay-rendezvous-v1".utf8)
    static let daySeconds: UInt64 = 86_400
    static let mailboxLen = 32

    /// Caixas prontas (hex) para publicar e assinar. `subscribe` traz 3 dias (ontem/hoje/amanhã) da
    /// direção do OUTRO lado — cobre virada de dia/fuso e o buffer semi-assíncrono do relay.
    public struct Endpoints: Equatable, Sendable {
        public let publish: String        // mailbox de HOJE, MINHA direção
        public let subscribe: [String]    // mailbox de ontem/hoje/amanhã, direção do OUTRO
    }

    /// Número do dia UTC. O núcleo NÃO lê o relógio: `epoch` (segundos desde 1970) é injetado pela
    /// camada de app, como no resto do BlackHoleCore.
    public static func dayBucket(epoch: Double) -> UInt64 {
        guard epoch > 0, epoch.isFinite else { return 0 }
        return UInt64(epoch) / daySeconds
    }

    /// API de alto nível: as caixas para publicar e assinar AGORA. `nil` se alguma chave não tem
    /// 32 B ou se as identidades são iguais (par inválido).
    public static func endpoints(myPrivateKey: Data, myPublicKey: Data, peerPublicKey: Data,
                                 epoch: Double) -> Endpoints? {
        guard let secret = pairSecret(myPrivateKey: myPrivateKey, peerPublicKey: peerPublicKey),
              let sendDir = sendDirection(myPublicKey: myPublicKey, peerPublicKey: peerPublicKey) else {
            return nil
        }
        let recvDir: UInt8 = 1 - sendDir
        let today = dayBucket(epoch: epoch)
        let publish = mailboxHex(pairSecret: secret, day: today, direction: sendDir)
        let subscribe = [today &- 1, today, today &+ 1].map {
            mailboxHex(pairSecret: secret, day: $0, direction: recvDir)
        }
        return Endpoints(publish: publish, subscribe: subscribe)
    }

    // MARK: - Peças internas (testáveis via @testable import)

    /// Segredo estável do par: X25519(minhaPriv, pubDoContato). Simétrico — os dois lados obtêm o
    /// mesmo valor. `nil` se as chaves não têm 32 B.
    static func pairSecret(myPrivateKey: Data, peerPublicKey: Data) -> Data? {
        guard myPrivateKey.count == 32, peerPublicKey.count == 32,
              let sk = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: myPrivateKey),
              let pk = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey),
              let shared = try? sk.sharedSecretFromKeyAgreement(with: pk) else { return nil }
        return shared.withUnsafeBytes { Data($0) }
    }

    /// Direção de ENVIO: a pública lexicograficamente MAIOR ("hi") publica em 0x01; a menor em 0x00.
    /// `nil` se as chaves não têm 32 B ou são iguais (par inválido — não há como partir a direção).
    static func sendDirection(myPublicKey: Data, peerPublicKey: Data) -> UInt8? {
        guard myPublicKey.count == 32, peerPublicKey.count == 32, myPublicKey != peerPublicKey else {
            return nil
        }
        // Eu sou "hi" se a minha pública é a MAIOR: peerPub < myPub.
        return lexLess(peerPublicKey, myPublicKey) ? 0x01 : 0x00
    }

    /// Caixa (32 B) para (dia, direção): HKDF sobre o segredo do par, com o dia e a direção no `info`.
    static func mailbox(pairSecret secret: Data, day: UInt64, direction: UInt8) -> Data {
        var info = Data(capacity: 9)
        withUnsafeBytes(of: day.bigEndian) { info.append(contentsOf: $0) }
        info.append(direction)
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret),
                                         salt: salt, info: info, outputByteCount: mailboxLen)
        return key.withUnsafeBytes { Data($0) }
    }

    static func mailboxHex(pairSecret secret: Data, day: UInt64, direction: UInt8) -> String {
        hex(mailbox(pairSecret: secret, day: day, direction: direction))
    }

    // MARK: - Helpers de bytes

    /// Comparação lexicográfica (mesma semântica do `lexLess` do Double Ratchet).
    static func lexLess(_ a: Data, _ b: Data) -> Bool {
        for (x, y) in zip(a, b) where x != y { return x < y }
        return a.count < b.count
    }

    static func hex(_ d: Data) -> String {
        let table = Array("0123456789abcdef")
        var s = String(); s.reserveCapacity(d.count * 2)
        for b in d { s.append(table[Int(b >> 4)]); s.append(table[Int(b & 0x0F)]) }
        return s
    }
}
