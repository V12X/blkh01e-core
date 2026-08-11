import Foundation
import CryptoKit
import Sodium

/// Parâmetros do Argon2id, PERSISTIDOS no `VaultEnvelope` (A1): abrir usa exatamente o mesmo
/// custo da criação, e permite endurecer o KDF numa versão futura sem bricar cofres.
public struct KDFParams: Codable, Equatable {
    public var opsLimit: Int
    public var memLimit: Int
    public var algorithm: Int  // 1 = Argon2id (v1.3). Tag estável nossa, não o rawValue da lib.

    public init(opsLimit: Int, memLimit: Int, algorithm: Int) {
        self.opsLimit = opsLimit
        self.memLimit = memLimit
        self.algorithm = algorithm
    }

    /// A ÚNICA força usada por cofres de produção. Ter um custo único e uniforme em TODO cofre
    /// é o que fecha o oráculo de timing do decoy (correção de regressão A3): `open()` real,
    /// `decoyWork()` e o ramo de envelope malformado pagam todos o MESMO custo.
    public static func standard() -> KDFParams { moderate() }

    static func moderate() -> KDFParams {
        let s = Sodium()
        return KDFParams(opsLimit: s.pwHash.OpsLimitModerate, memLimit: s.pwHash.MemLimitModerate, algorithm: 1)
    }
    static func sensitive() -> KDFParams {
        let s = Sodium()
        return KDFParams(opsLimit: s.pwHash.OpsLimitSensitive, memLimit: s.pwHash.MemLimitSensitive, algorithm: 1)
    }
    /// KDF barato — SOMENTE testes (internal). Produção nunca alcança (M1).
    static func testFast() -> KDFParams {
        let s = Sodium()
        return KDFParams(opsLimit: s.pwHash.OpsLimitInteractive, memLimit: s.pwHash.MemLimitInteractive, algorithm: 1)
    }

    /// Rejeita parâmetros fora de faixa sã lidos do disco (correção A1-DoS): um `memLimit`
    /// gigante adulterado no envelope viraria alocação enorme no Argon2id. Faixa = [interactive, sensitive].
    func withinSaneBounds() -> Bool {
        let s = Sodium()
        return algorithm == 1
            && opsLimit >= s.pwHash.OpsLimitInteractive && opsLimit <= s.pwHash.OpsLimitSensitive
            && memLimit >= s.pwHash.MemLimitInteractive && memLimit <= s.pwHash.MemLimitSensitive
    }
}

/// Esticamento de senha com Argon2id (libsodium). A senha NUNCA é persistida; só o salt e o
/// *ciphertext* da chave tocam o disco. Buffers de chave em claro são zerados.
public enum KeyDerivation {
    public static var saltLength: Int { Sodium().pwHash.SaltBytes }

    /// Fail-closed (M2): erro em vez de salt vazio silencioso.
    public static func newSalt() throws -> [UInt8] {
        let s = Sodium()
        guard let salt = s.randomBytes.buf(length: s.pwHash.SaltBytes) else { throw VaultError.randomFailure }
        return salt
    }

    public static func deriveKey(password: String, salt: [UInt8], params: KDFParams) throws -> SymmetricKey {
        let s = Sodium()
        guard params.withinSaneBounds(), salt.count == s.pwHash.SaltBytes else {
            throw VaultError.keyDerivationFailed
        }
        var pw = Array(password.utf8)
        guard var derived = s.pwHash.hash(outputLength: 32,
                                          passwd: pw,
                                          salt: salt,
                                          opsLimit: params.opsLimit,
                                          memLimit: params.memLimit,
                                          alg: .Argon2ID13) else {
            s.utils.zero(&pw)
            throw VaultError.keyDerivationFailed
        }
        defer { s.utils.zero(&derived); s.utils.zero(&pw) }   // higiene de RAM (M3)
        return SymmetricKey(data: derived)
    }
}
