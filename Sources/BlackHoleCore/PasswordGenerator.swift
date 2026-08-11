import Foundation

/// Gerador de senha forte. RNG do sistema (CSPRNG). Seleção UNIFORME via `randomElement(using:)`
/// (sem viés de módulo). GARANTE ao menos um caractere de cada classe habilitada — assim "com
/// símbolos" nunca produz uma senha sem símbolo por azar — e embaralha o resultado.
public enum PasswordGenerator {

    public struct Options: Equatable, Sendable {
        public var length: Int
        public var lowercase: Bool
        public var uppercase: Bool
        public var digits: Bool
        public var symbols: Bool

        public init(length: Int = 20, lowercase: Bool = true, uppercase: Bool = true,
                    digits: Bool = true, symbols: Bool = true) {
            self.length = length
            self.lowercase = lowercase; self.uppercase = uppercase
            self.digits = digits; self.symbols = symbols
        }

        /// Ao menos uma classe precisa estar ligada; senão vira `lowercase` (fail-safe).
        var effective: Options {
            (lowercase || uppercase || digits || symbols) ? self
                : Options(length: length, lowercase: true, uppercase: false, digits: false, symbols: false)
        }
    }

    static let lowers  = Array("abcdefghijkmnpqrstuvwxyz")       // sem l  (ambíguo com 1/I)
    static let uppers  = Array("ABCDEFGHJKLMNPQRSTUVWXYZ")       // sem I, O (ambíguos)
    static let digits  = Array("23456789")                      // sem 0, 1 (ambíguos)
    static let symbols = Array("!@#$%&*()-_=+[]{};:,.?")

    public static func generate(_ options: Options = .init()) -> String {
        var rng = SystemRandomNumberGenerator()
        return generate(options, using: &rng)
    }

    /// RNG injetável para testes; a API pública usa o `SystemRandomNumberGenerator` (CSPRNG).
    static func generate<R: RandomNumberGenerator>(_ options: Options, using rng: inout R) -> String {
        let opts = options.effective
        var classes: [[Character]] = []
        if opts.lowercase { classes.append(lowers) }
        if opts.uppercase { classes.append(uppers) }
        if opts.digits    { classes.append(digits) }
        if opts.symbols   { classes.append(symbols) }

        let alphabet = classes.flatMap { $0 }
        // Comprimento efetivo cabe ao menos 1 de cada classe.
        let length = max(opts.length, classes.count)

        var chars: [Character] = []
        for cls in classes { chars.append(cls.randomElement(using: &rng)!) }   // 1 garantido por classe
        while chars.count < length { chars.append(alphabet.randomElement(using: &rng)!) }
        chars.shuffle(using: &rng)
        return String(chars)
    }
}
