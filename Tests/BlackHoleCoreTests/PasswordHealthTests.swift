import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Saúde das senhas: heurística de fraqueza, reuso por hash, k-anonymity do HIBP (vetor fixo) e o
/// marcador opt-in do check de vazamento.
@MainActor
final class PasswordHealthTests: XCTestCase {

    // MARK: - Fraca

    func testIsWeak_rules() {
        XCTAssertTrue(PasswordHealth.isWeak("curta1!"), "curta demais")
        XCTAssertTrue(PasswordHealth.isWeak("123456789012345"), "uma classe só (dígitos)")
        XCTAssertTrue(PasswordHealth.isWeak("abcdefghijklmno"), "uma classe só (minúsculas)")
        XCTAssertFalse(PasswordHealth.isWeak("abcdefghijkl9"), "12+ com duas classes")
        XCTAssertFalse(PasswordHealth.isWeak("Tr4ns-p0nte!Coruja"), "forte")
    }

    // MARK: - Reuso

    func testReusedGroups() {
        let groups = PasswordHealth.reusedGroups([
            (id: "a", password: "mesma-senha-123"),
            (id: "b", password: "outra-senha-456"),
            (id: "c", password: "mesma-senha-123"),
            (id: "d", password: "terceira-789"),
            (id: "e", password: "mesma-senha-123"),
        ])
        XCTAssertEqual(groups, [["a", "c", "e"]])
        XCTAssertTrue(PasswordHealth.reusedGroups([(id: "x", password: "só-uma")]).isEmpty)
    }

    // MARK: - HIBP k-anonymity

    /// Vetor conhecido: SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
    func testHibpParts_knownVector() {
        let (prefix, suffix) = PasswordHealth.hibpParts("password")
        XCTAssertEqual(prefix, "5BAA6")
        XCTAssertEqual(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
        XCTAssertEqual(prefix.count, 5, "SÓ 5 hex saem do aparelho")
    }

    func testBreachCount_parser() {
        let body = """
        0018A45C4D1DEF81644B54AB7F969B88D65:1
        1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824
        011053FD0102E94D6AE2F8B83D76FAF94F6:0
        linha-malformada
        """
        XCTAssertEqual(PasswordHealth.breachCount(inRangeResponse: body,
                                                  suffix: "1e4c9b93f3f0682250b6cf8331b7ee68fd8"),
                       9_545_824, "case-insensitive")
        XCTAssertEqual(PasswordHealth.breachCount(inRangeResponse: body,
                                                  suffix: "011053FD0102E94D6AE2F8B83D76FAF94F6"),
                       0, "padding com contagem 0 = não vazada")
        XCTAssertEqual(PasswordHealth.breachCount(inRangeResponse: body, suffix: "FFFF"), 0)
    }

    // MARK: - Marcador opt-in

    func testBreachFlag_defaultOff_persists() throws {
        let vault = Vault(device: SoftwareDeviceKeystore(key: SymmetricKey(data: Data(repeating: 7, count: 32))))
        let (_, session) = try vault.create(password: "s3nha", kdf: .testFast())
        let blobs = InMemoryBlobStore()
        let store = try VaultStore(session: session, blobs: blobs)

        XCTAssertFalse(store.breachCheckEnabled(), "rede é opt-IN: default DESLIGADO")
        try store.setBreachCheckEnabled(true)
        XCTAssertTrue(store.breachCheckEnabled())

        let reopened = try VaultStore(session: session, blobs: blobs)
        XCTAssertTrue(reopened.breachCheckEnabled(), "sobrevive à releitura")
        try reopened.setBreachCheckEnabled(false)
        XCTAssertFalse(reopened.breachCheckEnabled())
    }
}
