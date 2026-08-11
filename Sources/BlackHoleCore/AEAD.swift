import Foundation
import CryptoKit

/// AEAD = ChaCha20-Poly1305 (CryptoKit, auditado pela Apple). O CryptoKit gera um nonce
/// aleatório de 96 bits por selagem. `combined` = nonce || ciphertext || tag.
///
/// Nota de nonce: a chave-por-arquivo (FEK) cifra 1 mensagem, então nunca há reuso. A
/// chave-mestra (MK) reembrulha N chaves-de-arquivo; com nonce aleatório de 96 bits, colisão
/// só é preocupante perto de ~2^32 selagens sob a MESMA chave — muito acima do volume de um
/// cofre de consumidor. Se a contagem sob a MK puder crescer sem limite, migrar para nonce-
/// contador. (Ponto confirmado como não-vulnerabilidade na revisão de cripto nº1.)
enum AEAD {
    static func seal(_ plaintext: Data, key: SymmetricKey, aad: Data = Data()) throws -> Data {
        let box = try ChaChaPoly.seal(plaintext, using: key, authenticating: aad)
        return box.combined
    }

    /// Retorna o plaintext, ou `nil` se a autenticação falhar (chave errada / adulteração / AAD divergente).
    static func open(_ combined: Data, key: SymmetricKey, aad: Data = Data()) -> Data? {
        guard let box = try? ChaChaPoly.SealedBox(combined: combined) else { return nil }
        return try? ChaChaPoly.open(box, using: key, authenticating: aad)
    }
}
