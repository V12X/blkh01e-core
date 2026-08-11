import Foundation
import CryptoKit

/// Saúde das senhas: análise LOCAL (funções puras, testáveis headless) + a parte determinística do
/// k-anonymity do HIBP. NADA aqui faz IO — a rede (opt-in) fica na camada de app.
public enum PasswordHealth {

    /// Fraca = curta demais OU uma classe só de caracteres. Heurística deliberadamente simples e
    /// EXPLICÁVEL na UI (a filosofia do produto é indicador factual, não score opaco 0-100).
    public static func isWeak(_ password: String) -> Bool {
        if password.count < 12 { return true }
        var classes = 0
        if password.contains(where: { $0.isLowercase }) { classes += 1 }
        if password.contains(where: { $0.isUppercase }) { classes += 1 }
        if password.contains(where: { $0.isNumber }) { classes += 1 }
        if password.contains(where: { !$0.isLetter && !$0.isNumber }) { classes += 1 }
        return classes < 2
    }

    /// Grupos de REUSO: ids que compartilham a MESMA senha. Compara por hash (SHA-256) — o chamador
    /// pode descartar os plaintexts logo depois; nada fica retido aqui.
    public static func reusedGroups(_ secrets: [(id: String, password: String)]) -> [[String]] {
        var byHash: [String: [String]] = [:]
        for s in secrets {
            let h = SHA256.hash(data: Data(s.password.utf8)).map { String(format: "%02x", $0) }.joined()
            byHash[h, default: []].append(s.id)
        }
        return byHash.values.filter { $0.count > 1 }.map { $0.sorted() }.sorted { $0[0] < $1[0] }
    }

    /// k-anonymity do HIBP: SHA-1 da senha; SAEM só os 5 primeiros hex (casam com ~800 senhas
    /// diferentes — inespecífico por construção); o SUFIXO compara LOCALMENTE contra a resposta.
    /// A senha nunca sai do aparelho, nem inteira nem hasheada por completo.
    public static func hibpParts(_ password: String) -> (prefix: String, suffix: String) {
        let hex = Insecure.SHA1.hash(data: Data(password.utf8))
            .map { String(format: "%02X", $0) }.joined()
        return (String(hex.prefix(5)), String(hex.dropFirst(5)))
    }

    /// Procura o sufixo na resposta do range (linhas "SUFFIX:COUNT"). 0 = não consta. Parser
    /// defensivo: linha malformada é ignorada; com o header Add-Padding o servidor inclui sufixos
    /// de contagem 0 — 0 continua significando "não vazada".
    public static func breachCount(inRangeResponse body: String, suffix: String) -> Int {
        let want = suffix.uppercased()
        for line in body.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2,
                  parts[0].trimmingCharacters(in: .whitespaces).uppercased() == want else { continue }
            return Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0
        }
        return 0
    }
}
