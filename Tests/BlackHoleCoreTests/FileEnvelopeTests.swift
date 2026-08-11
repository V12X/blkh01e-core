import XCTest
@testable import BlackHoleCore

/// Envelope de nome+tipo embrulhado no texto claro antes do `SecureFile`. Round-trip, retrocompat
/// (bytes crus antigos = legado), robustez a comprimentos mentirosos, e integração com o SecureFile.
final class FileEnvelopeTests: XCTestCase {

    // MARK: - Round-trip

    func testWrapUnwrap_preservesNameUTIData() {
        let payload = Data("um áudio qualquer 🎧".utf8)
        let wrapped = FileEnvelope.wrap(payload, name: "gravação.m4a", uti: "public.mpeg-4-audio")
        let d = FileEnvelope.unwrap(wrapped)
        XCTAssertEqual(d.name, "gravação.m4a")
        XCTAssertEqual(d.uti, "public.mpeg-4-audio")
        XCTAssertEqual(d.data, payload)
        XCTAssertFalse(d.isLegacy)
    }

    func testWrapUnwrap_emptyUTIBecomesNil() {
        let d = FileEnvelope.unwrap(FileEnvelope.wrap(Data("x".utf8), name: "a.bin", uti: nil))
        XCTAssertEqual(d.name, "a.bin")
        XCTAssertNil(d.uti)
    }

    func testWrapUnwrap_emptyPayload() {
        let d = FileEnvelope.unwrap(FileEnvelope.wrap(Data(), name: "vazio", uti: nil))
        XCTAssertEqual(d.name, "vazio")
        XCTAssertEqual(d.data, Data())
    }

    // MARK: - Retrocompat (legado)

    func testUnwrap_rawBytes_isLegacy() {
        // Bytes que NÃO começam com "BHE1" (ex.: JPEG começa com FF D8 FF).
        let raw = Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46])
        let d = FileEnvelope.unwrap(raw)
        XCTAssertTrue(d.isLegacy)
        XCTAssertNil(d.name)
        XCTAssertEqual(d.data, raw)      // conteúdo intacto
    }

    func testUnwrap_shortBytes_isLegacy() {
        let d = FileEnvelope.unwrap(Data([1, 2, 3]))
        XCTAssertTrue(d.isLegacy)
        XCTAssertEqual(d.data, Data([1, 2, 3]))
    }

    // MARK: - Robustez a comprimento mentiroso

    func testUnwrap_lyingNameLen_fallsBackToLegacy() {
        // magic + version + nameLen enorme, mas sem bytes suficientes → legado, sem crash.
        var b = Data("BHE1".utf8)
        b.append(1)                       // version
        b.append(0xFF); b.append(0xFF)    // nameLen = 65535
        b.append(contentsOf: [0x41, 0x42])
        let d = FileEnvelope.unwrap(b)
        XCTAssertTrue(d.isLegacy)         // recusou o comprimento, tratou como cru
        XCTAssertEqual(d.data, b)
    }

    func testUnwrap_wrongVersion_isLegacy() {
        var b = Data("BHE1".utf8)
        b.append(99)                      // versão desconhecida
        b.append(0x00); b.append(0x01); b.append(0x41)
        b.append(0x00); b.append(0x00)
        XCTAssertTrue(FileEnvelope.unwrap(b).isLegacy)
    }

    // MARK: - Integração com SecureFile

    func testSealWrap_openUnwrap_roundTrip() throws {
        let payload = Data((0..<5000).map { UInt8($0 & 0xFF) })
        let wrapped = FileEnvelope.wrap(payload, name: "documento.pdf", uti: "com.adobe.pdf")
        let sealed = try SecureFile.seal(wrapped, password: "combinada", params: .testFast())
        let opened = try SecureFile.open(sealed, password: "combinada")
        let d = FileEnvelope.unwrap(opened)
        XCTAssertEqual(d.name, "documento.pdf")
        XCTAssertEqual(d.uti, "com.adobe.pdf")
        XCTAssertEqual(d.data, payload)
    }

    func testLegacyImageFlow_stillOpensAsLegacy() throws {
        // Fluxo ANTIGO: imagem crua cifrada direto (sem envelope). Deve abrir como legado.
        let fakeImage = Data([0xFF, 0xD8, 0xFF] + (0..<1000).map { UInt8($0 & 0xFF) })
        let sealed = try SecureFile.seal(fakeImage, password: "pw", params: .testFast())
        let d = FileEnvelope.unwrap(try SecureFile.open(sealed, password: "pw"))
        XCTAssertTrue(d.isLegacy)
        XCTAssertEqual(d.data, fakeImage)
    }

    // MARK: - Nome não vaza no cifrado

    func testSealedWrap_hidesFilename() throws {
        let sealed = try SecureFile.seal(
            FileEnvelope.wrap(Data("x".utf8), name: "NOME-SECRETO.m4a", uti: nil),
            password: "pw", params: .testFast())
        XCTAssertNil(sealed.range(of: Data("NOME-SECRETO".utf8)))   // cifrado junto
    }
}
