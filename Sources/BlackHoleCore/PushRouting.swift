import Foundation
import CryptoKit

/// Endereçamento do **push relay** (aviso confiável, §"Push Relay" em `docs/push-relay-design.md`).
/// NÃO toca a criptografia das mensagens — só decide qual identificador OPACO um remetente usa para
/// "acordar" o destinatário. O relay nunca vê o conteúdo, os contatos, nem os mailboxes Nostr.
///
/// Mesma ideia do `RelayRendezvous` (segredo do par por X25519, sem handshake, cada lado calcula
/// sozinho) — aqui aplicada a UM valor estável por contato, não um que rotaciona por dia. Rotação
/// diária faria sentido se o REGISTRO fosse rederivado todo dia, mas isso exigiria o app rodar em
/// background com confiabilidade, que é exatamente o problema que o relay existe pra resolver.
/// Trade-off honesto: o identificador de registro NÃO rotaciona; a mitigação é o relay reter nada
/// (zero-retenção) e o registro reexpirar sozinho (o app do dono reregistra a cada abertura).
///
/// ==================== PUSH ROUTING v1 — CONGELADO ====================
///   segredoDoPar = X25519(minhaIdentidadePriv, identidadePubDoContato)   // 32 B, o MESMO do
///                                                                        // RelayRendezvous
///   (lo, hi)     = ordem lexicográfica das DUAS identidades públicas (mesmo critério)
///   direção(pub) = (pub == hi) ? 0x01 : 0x00                             // "de quem" o par é
///   routingID(d) = HKDF-SHA256(ikm=segredoDoPar, salt="BLKH01E/push-routing-v1",
///                              info = byte(d) || 0x01, L=16)             // 16 B → base64url
///   proof(d)     = HKDF-SHA256(ikm=segredoDoPar, salt="BLKH01E/push-routing-v1",
///                              info = byte(d) || 0x02, L=16)             // 16 B → base64url
///
///   REGISTRO (o dono de `d` faz, uma vez por contato, ao ligar o aviso por push):
///     POST /register { routingID: routingID(d), proofHash: SHA256(proof(d)), token: <APNs> }
///   ACORDAR (o REMETENTE calcula sozinho a direção do OUTRO lado):
///     POST /wake     { routingID: routingID(dOutro), proof: proof(dOutro) }
///
///   O relay guarda `proofHash`, nunca `proof` — não pode se autoacordar nem provar a um terceiro
///   que aquele contato existe. Só quem fez o X25519 com a chave pública real (troca de QR
///   presencial) consegue calcular `routingID`/`proof`: a posse de um `routingID` válido já prova
///   "sou contato de verdade" — não muda o modelo de ameaça publicar este arquivo.
/// Qualquer mudança neste layout exige uma versão nova (salt/`v2`).
/// =======================================================================
public enum PushRouting {
    static let salt = Data("BLKH01E/push-routing-v1".utf8)
    /// 16 B (128 bits): espaço grande o bastante para nunca colidir, pequeno o bastante para não
    /// pesar no payload JSON do registro/wake.
    static let idLen = 16

    public struct Credential: Equatable, Sendable {
        public let routingID: Data    // 16 B, opaco
        public let proof: Data        // 16 B, só sai do aparelho no /wake — nunca no /register
    }

    /// Minha própria direção neste par: quem tem a pública lexicograficamente MAIOR é "hi" (0x01).
    /// Mesma regra do `RelayRendezvous.sendDirection`, reaproveitada por igualdade de critério (não
    /// por chamada direta — este tipo fica testável isoladamente).
    static func direction(myPublicKey: Data, peerPublicKey: Data) -> UInt8? {
        guard myPublicKey.count == 32, peerPublicKey.count == 32, myPublicKey != peerPublicKey else {
            return nil
        }
        return RelayRendezvous.lexLess(peerPublicKey, myPublicKey) ? 0x01 : 0x00
    }

    /// A credencial que EU registro no relay (para SEREM acordado por este contato).
    public static func mine(myPrivateKey: Data, myPublicKey: Data, peerPublicKey: Data) -> Credential? {
        guard let secret = RelayRendezvous.pairSecret(myPrivateKey: myPrivateKey, peerPublicKey: peerPublicKey),
              let d = direction(myPublicKey: myPublicKey, peerPublicKey: peerPublicKey) else { return nil }
        return Credential(routingID: derive(secret, d, 0x01), proof: derive(secret, d, 0x02))
    }

    /// A credencial do CONTATO (calculada por mim, para acordá-lo — nunca a peço a ele).
    public static func forPeer(myPrivateKey: Data, myPublicKey: Data, peerPublicKey: Data) -> Credential? {
        guard let secret = RelayRendezvous.pairSecret(myPrivateKey: myPrivateKey, peerPublicKey: peerPublicKey),
              let myDir = direction(myPublicKey: myPublicKey, peerPublicKey: peerPublicKey) else { return nil }
        let peerDir: UInt8 = 1 - myDir
        return Credential(routingID: derive(secret, peerDir, 0x01), proof: derive(secret, peerDir, 0x02))
    }

    private static func derive(_ secret: Data, _ dir: UInt8, _ tag: UInt8) -> Data {
        let info = Data([dir, tag])
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret),
                                         salt: salt, info: info, outputByteCount: idLen)
        return key.withUnsafeBytes { Data($0) }
    }
}
