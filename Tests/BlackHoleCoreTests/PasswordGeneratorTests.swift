import XCTest
@testable import BlackHoleCore

/// Gerador de senha: propriedades garantidas por construção (comprimento, classes presentes,
/// alfabeto restrito, fail-safe). Não testa saída exata — RNG é CSPRNG; testa invariantes.
final class PasswordGeneratorTests: XCTestCase {

    private func has(_ s: String, in set: [Character]) -> Bool {
        s.contains { set.contains($0) }
    }

    func testDefault_lengthAndAllClassesPresent() {
        for _ in 0..<50 {                                  // repete: a garantia é por construção, não sorte
            let p = PasswordGenerator.generate(.init(length: 20))
            XCTAssertEqual(p.count, 20)
            XCTAssertTrue(has(p, in: PasswordGenerator.lowers), "tem minúscula")
            XCTAssertTrue(has(p, in: PasswordGenerator.uppers), "tem maiúscula")
            XCTAssertTrue(has(p, in: PasswordGenerator.digits), "tem dígito")
            XCTAssertTrue(has(p, in: PasswordGenerator.symbols), "tem símbolo")
        }
    }

    func testOnlyDigits_restrictsAlphabet() {
        let p = PasswordGenerator.generate(.init(length: 16, lowercase: false, uppercase: false, digits: true, symbols: false))
        XCTAssertEqual(p.count, 16)
        XCTAssertTrue(p.allSatisfy { PasswordGenerator.digits.contains($0) }, "só dígitos")
    }

    func testNoClassSelected_failsSafeToLowercase() {
        let p = PasswordGenerator.generate(.init(length: 12, lowercase: false, uppercase: false, digits: false, symbols: false))
        XCTAssertEqual(p.count, 12)
        XCTAssertTrue(p.allSatisfy { PasswordGenerator.lowers.contains($0) }, "fail-safe: minúsculas")
    }

    /// Comprimento pedido menor que o nº de classes → sobe para caber 1 de cada.
    func testLengthBelowClassCount_bumpsToFitOnePerClass() {
        let p = PasswordGenerator.generate(.init(length: 2))   // 4 classes ligadas
        XCTAssertEqual(p.count, 4)
    }

    func testAmbiguousCharsExcluded() {
        let ambiguous: Set<Character> = ["l", "I", "O", "0", "1"]
        let p = PasswordGenerator.generate(.init(length: 200))
        XCTAssertFalse(p.contains { ambiguous.contains($0) }, "sem caracteres ambíguos")
    }

    func testTwoGenerations_differ() {
        let a = PasswordGenerator.generate(.init(length: 24))
        let b = PasswordGenerator.generate(.init(length: 24))
        XCTAssertNotEqual(a, b, "entropia: duas gerações não coincidem")
    }
}
