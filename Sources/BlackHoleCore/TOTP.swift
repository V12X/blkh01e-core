import Foundation
import CryptoKit

/// TOTP (RFC 6238) sobre HOTP (RFC 4226) — o mecanismo do "Google Authenticator": um segredo
/// compartilhado + o relógio → HMAC → código de 6–8 dígitos que troca a cada período (30 s).
/// É matemática 100% LOCAL: sem rede, sem conta, sem servidor — o mundo deste app. O segredo
/// vive cifrado no cofre como qualquer outro conteúdo.
///
/// Nota sobre SHA-1 (postura de "só primitivas auditadas"): o padrão TOTP usa HMAC-SHA1. HMAC
/// não depende de resistência a COLISÃO — os ataques conhecidos ao SHA-1 não se aplicam a
/// HMAC-SHA1, que segue considerado seguro para autenticação (RFC 6194). Suportamos também
/// SHA-256/512, usados quando o provedor os pedir no URI.
public enum TOTP {
    public enum Algorithm: String, Codable, CaseIterable, Sendable {
        case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512"
    }

    /// Uma conta 2FA importada (QR `otpauth://` ou digitação manual). `secret` são os BYTES CRUS
    /// (já decodificados do Base32) — o que se persiste, cifrado, no cofre.
    public struct Account: Codable, Equatable, Sendable {
        public var secret: Data
        public var issuer: String       // provedor ("GitHub") — pode ser vazio
        public var label: String        // conta ("ana@exemplo.com") — pode ser vazio
        public var digits: Int          // 6–8 (6 é o padrão de mercado)
        public var period: Int          // segundos por janela (30 padrão)
        public var algorithm: Algorithm

        public init(secret: Data, issuer: String = "", label: String = "",
                    digits: Int = 6, period: Int = 30, algorithm: Algorithm = .sha1) {
            self.secret = secret
            self.issuer = issuer
            self.label = label
            self.digits = digits
            self.period = period
            self.algorithm = algorithm
        }
    }

    // MARK: - Base32 (RFC 4648) — como os segredos chegam nos QRs

    /// Decodifica Base32 padrão (A–Z, 2–7). Tolerante ao que os apps reais emitem: minúsculas,
    /// espaços/hífens de agrupamento e `=` de padding. Qualquer outro caractere → nil (entrada
    /// de QR é canal hostil; não adivinhamos).
    public static func base32Decode(_ s: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var index = [Character: UInt32]()
        for (i, c) in alphabet.enumerated() { index[c] = UInt32(i) }

        var bits: UInt32 = 0
        var bitCount = 0
        var out = Data()
        for raw in s.uppercased() {
            if raw == "=" || raw == " " || raw == "-" { continue }
            guard let v = index[raw] else { return nil }
            bits = (bits << 5) | v
            bitCount += 5
            if bitCount >= 8 {
                bitCount -= 8
                out.append(UInt8((bits >> UInt32(bitCount)) & 0xFF))
            }
        }
        return out
    }

    // MARK: - HOTP (RFC 4226) e TOTP (RFC 6238)

    /// HOTP: HMAC(chave, contador BE-64) → truncagem dinâmica → `digits` dígitos com zeros à
    /// esquerda. `nil` para parâmetros fora da faixa (segredo vazio, digits fora de 6–8).
    public static func hotp(secret: Data, counter: UInt64,
                            digits: Int = 6, algorithm: Algorithm = .sha1) -> String? {
        guard !secret.isEmpty, (6...8).contains(digits) else { return nil }
        var c = counter.bigEndian
        let msg = withUnsafeBytes(of: &c) { Data($0) }
        let key = SymmetricKey(data: secret)
        let mac: Data
        switch algorithm {
        case .sha1:   mac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: key))
        case .sha256: mac = Data(HMAC<SHA256>.authenticationCode(for: msg, using: key))
        case .sha512: mac = Data(HMAC<SHA512>.authenticationCode(for: msg, using: key))
        }
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let bin = (UInt32(mac[offset] & 0x7F) << 24)
                | (UInt32(mac[offset + 1]) << 16)
                | (UInt32(mac[offset + 2]) << 8)
                |  UInt32(mac[offset + 3])
        let mod = UInt32(pow(10, Double(digits)))
        return String(format: "%0\(digits)d", bin % mod)
    }

    /// O código ATUAL da conta no instante dado. `nil` = conta malformada.
    public static func code(for account: Account, at date: Date = Date()) -> String? {
        guard account.period > 0 else { return nil }
        let counter = UInt64(max(0, date.timeIntervalSince1970)) / UInt64(account.period)
        return hotp(secret: account.secret, counter: counter,
                    digits: account.digits, algorithm: account.algorithm)
    }

    /// Segundos até o código atual expirar (para o anel de contagem da UI). Sempre em 1...period.
    public static func secondsRemaining(period: Int = 30, at date: Date = Date()) -> Int {
        guard period > 0 else { return 0 }
        let t = UInt64(max(0, date.timeIntervalSince1970))
        return period - Int(t % UInt64(period))
    }

    // MARK: - otpauth:// (o formato dos QRs de 2FA)

    /// Lê um URI `otpauth://totp/Emissor:conta?secret=...&issuer=...&digits=6&period=30&algorithm=SHA1`.
    /// Só o tipo `totp` (o `hotp` de contador é raro e fica de fora por ora). `nil` = malformado —
    /// entrada de QR é hostil, então validação estrita: secret Base32 válido e não-vazio, digits
    /// 6–8, period 1–300, algoritmo conhecido.
    public static func parse(otpauthURI: String) -> Account? {
        guard let comps = URLComponents(string: otpauthURI),
              comps.scheme?.lowercased() == "otpauth",
              comps.host?.lowercased() == "totp" else { return nil }

        var secret: Data?
        var issuer = ""
        var digits = 6
        var period = 30
        var algorithm = Algorithm.sha1
        for item in comps.queryItems ?? [] {
            let v = item.value ?? ""
            switch item.name.lowercased() {
            case "secret":
                guard let d = base32Decode(v), !d.isEmpty else { return nil }
                secret = d
            case "issuer":    issuer = v
            case "digits":    guard let n = Int(v), (6...8).contains(n) else { return nil }; digits = n
            case "period":    guard let n = Int(v), (1...300).contains(n) else { return nil }; period = n
            case "algorithm": guard let a = Algorithm(rawValue: v.uppercased()) else { return nil }; algorithm = a
            default: break   // parâmetros desconhecidos são ignorados (compat futura)
            }
        }
        guard let sec = secret else { return nil }

        // Rótulo do path: "/Emissor:conta" ou "/conta" (percent-decoding já feito pelo URLComponents).
        var label = comps.path.hasPrefix("/") ? String(comps.path.dropFirst()) : comps.path
        if let colon = label.firstIndex(of: ":") {
            let pathIssuer = String(label[..<colon]).trimmingCharacters(in: .whitespaces)
            label = String(label[label.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if issuer.isEmpty { issuer = pathIssuer }   // o parâmetro `issuer` tem precedência
        }
        return Account(secret: sec, issuer: issuer, label: label,
                       digits: digits, period: period, algorithm: algorithm)
    }
}
