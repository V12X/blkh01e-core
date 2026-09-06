import Foundation

/// Importação do QR de exportação do **Google Authenticator** (`otpauth-migration://offline?data=…`).
///
/// É a única porta de saída daquele app: ele NÃO exporta texto, só um (ou vários) QR com um
/// protobuf embrulhado em Base64. Sem ler esse formato, migrar significa recadastrar conta por
/// conta em cada site — o custo real que prende as pessoas onde estão.
///
/// O payload é lido com um leitor de protobuf MÍNIMO escrito aqui (varint + campos delimitados por
/// tamanho): trazer uma biblioteca de protobuf para ler ~7 campos seria mais superfície de ataque
/// do que o problema pede. Entrada de QR é canal HOSTIL — todo tamanho é conferido contra o que
/// resta do buffer, campos desconhecidos são pulados e nada é adivinhado.
///
/// ## Formato (protobuf `MigrationPayload`, engenharia reversa pública e estável desde 2020)
/// ```
/// MigrationPayload { repeated OtpParameters otp_parameters = 1; int32 version = 2;
///                    int32 batch_size = 3; int32 batch_index = 4; bytes batch_id = 5 }
/// OtpParameters { bytes secret = 1; string name = 2; string issuer = 3;
///                 Algorithm algorithm = 4;   // 1=SHA1 2=SHA256 3=SHA512 4=MD5
///                 DigitCount digits = 5;     // 1=SIX 2=EIGHT
///                 OtpType type = 6;          // 1=HOTP 2=TOTP
///                 int64 counter = 7 }
/// ```
public enum TOTPMigration {

    /// O que veio no QR. `skippedHOTP` e `batch*` existem para a UI poder ser HONESTA: o Google
    /// divide a exportação em VÁRIOS QRs e quem escaneia um só levaria parte das contas sem saber.
    public struct Result: Equatable, Sendable {
        public var accounts: [TOTP.Account]
        /// Contas HOTP (baseadas em contador) encontradas e ignoradas — o cofre guarda TOTP.
        public var skippedHOTP: Int
        /// "QR `batchIndex + 1` de `batchSize`". Ambos 0 quando o payload não os traz.
        public var batchIndex: Int
        public var batchSize: Int

        public init(accounts: [TOTP.Account], skippedHOTP: Int = 0, batchIndex: Int = 0, batchSize: Int = 0) {
            self.accounts = accounts; self.skippedHOTP = skippedHOTP
            self.batchIndex = batchIndex; self.batchSize = batchSize
        }
    }

    /// Lê o URI do QR. `nil` = não é um QR de migração válido (esquema errado, Base64 inválido,
    /// protobuf malformado). Um payload válido SEM contas devolve `Result` com lista vazia — quem
    /// chama distingue "não é isso" de "é isso e está vazio".
    public static func parse(migrationURI: String) -> Result? {
        guard let comps = URLComponents(string: migrationURI),
              comps.scheme?.lowercased() == "otpauth-migration" else { return nil }
        guard let raw = comps.queryItems?.first(where: { $0.name.lowercased() == "data" })?.value,
              !raw.isEmpty else { return nil }
        // O Google emite Base64 PADRÃO (com + / =). O `URLComponents` já tira o percent-encoding,
        // mas "+" dentro de query vira espaço em alguns leitores — desfazemos.
        let b64 = raw.replacingOccurrences(of: " ", with: "+")
        guard let payload = Data(base64Encoded: b64) else { return nil }
        return parse(payload: payload)
    }

    /// Lê o protobuf já decodificado do Base64.
    public static func parse(payload: Data) -> Result? {
        var r = Reader(payload)
        var accounts: [TOTP.Account] = []
        var skipped = 0
        var batchIndex = 0, batchSize = 0
        while let field = r.nextField() {
            switch (field.number, field.value) {
            case (1, .bytes(let d)):                       // otp_parameters
                switch parseParameters(d) {
                case .totp(let a): accounts.append(a)
                case .hotp: skipped += 1
                case .invalid: return nil                   // um item quebrado invalida o QR
                }
            case (3, .varint(let v)): batchSize = Int(truncatingIfNeeded: Int64(bitPattern: v))
            case (4, .varint(let v)): batchIndex = Int(truncatingIfNeeded: Int64(bitPattern: v))
            default: break                                  // version, batch_id e futuros: ignorados
            }
        }
        guard r.consumedAll else { return nil }
        return Result(accounts: accounts, skippedHOTP: skipped, batchIndex: batchIndex, batchSize: batchSize)
    }

    private enum Parsed { case totp(TOTP.Account), hotp, invalid }

    private static func parseParameters(_ d: Data) -> Parsed {
        var r = Reader(d)
        var secret = Data(), name = "", issuer = ""
        var algorithm = TOTP.Algorithm.sha1
        var digits = 6
        var isTOTP = true          // `type` ausente: o QR do Google sempre traz TOTP
        var sawType = false
        while let field = r.nextField() {
            switch (field.number, field.value) {
            case (1, .bytes(let v)): secret = v
            case (2, .bytes(let v)): name = String(decoding: v, as: UTF8.self)
            case (3, .bytes(let v)): issuer = String(decoding: v, as: UTF8.self)
            case (4, .varint(let v)):
                switch v {
                case 0, 1: algorithm = .sha1               // 0 = não especificado → padrão
                case 2:    algorithm = .sha256
                case 3:    algorithm = .sha512
                default:   return .invalid                 // MD5 (4) não é suportado: recusar > fingir
                }
            case (5, .varint(let v)):
                switch v {
                case 0, 1: digits = 6
                case 2:    digits = 8
                default:   return .invalid
                }
            case (6, .varint(let v)):
                sawType = true
                switch v {
                case 1: isTOTP = false                     // HOTP: contador, fora do escopo do cofre
                case 0, 2: isTOTP = true
                default: return .invalid
                }
            default: break                                  // counter e futuros: ignorados
            }
        }
        guard r.consumedAll, !secret.isEmpty else { return .invalid }
        guard isTOTP || !sawType else { return .hotp }
        // O Google não exporta `period`: a exportação é sempre de 30 s (não há como configurar lá).
        return .totp(TOTP.Account(secret: secret, issuer: issuer, label: name,
                                  digits: digits, period: 30, algorithm: algorithm))
    }

    // MARK: - Leitor de protobuf mínimo

    private struct Reader {
        enum Value { case varint(UInt64), bytes(Data), fixed }
        struct Field { let number: Int; let value: Value }

        private let d: Data
        private var i: Int
        /// Buffer inválido. Existe porque "acabou o buffer" e "byte inválido" davam o MESMO sinal
        /// (nil) e o leitor já tinha consumido os bytes — um payload truncado passava por completo.
        private(set) var failed = false
        init(_ d: Data) { self.d = d; self.i = d.startIndex }
        var consumedAll: Bool { !failed && i == d.endIndex }
        private var remaining: Int { d.endIndex - i }

        /// Próximo campo; nil no fim do buffer OU em erro — quem chama olha `consumedAll`.
        mutating func nextField() -> Field? {
            guard !failed, remaining > 0 else { return nil }     // fim limpo
            guard let key = varint() else { failed = true; return nil }
            let number = Int(key >> 3)
            guard number > 0 else { failed = true; return nil }
            switch key & 0x07 {
            case 0:
                guard let v = varint() else { failed = true; return nil }
                return Field(number: number, value: .varint(v))
            case 2:
                guard let len = varint(), len <= UInt64(remaining) else { failed = true; return nil }
                let n = Int(len)
                let out = d.subdata(in: i..<(i + n))
                i += n
                return Field(number: number, value: .bytes(out))
            case 1, 5:
                let n = (key & 0x07) == 1 ? 8 : 4          // 64/32 bits: pular, não interpretar
                guard n <= remaining else { failed = true; return nil }
                i += n
                return Field(number: number, value: .fixed)
            default:
                failed = true                              // grupos (3/4): mortos desde o proto2
                return nil
            }
        }

        private mutating func varint() -> UInt64? {
            var out: UInt64 = 0, shift: UInt64 = 0
            while i < d.endIndex {
                let b = d[i]; i += 1
                guard shift <= 63 else { return nil }        // varint maior que 64 bits: hostil
                out |= UInt64(b & 0x7F) << shift
                if b & 0x80 == 0 { return out }
                shift += 7
            }
            return nil                                       // acabou no meio do varint
        }
    }
}
