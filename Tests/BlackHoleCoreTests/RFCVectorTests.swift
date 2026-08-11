import XCTest
import CryptoKit
@testable import BlackHoleCore

/// Vetores de REFERÊNCIA EXTERNA (RFCs + implementações independentes). Os FrozenVectorTests
/// provam que o formato não regride contra si mesmo; estes provam que as primitivas batem com
/// os PADRÕES PÚBLICOS — o primeiro item que um auditor externo procura num core aberto.
///
///  - X25519            → RFC 7748 §5.2 (scalar mult) e §6.1 (DH Alice/Bob)
///  - ChaCha20-Poly1305  → RFC 8439 §2.8.2 (AEAD com AAD)
///  - HKDF-SHA256        → RFC 5869 Apêndice A (casos 1 e 3)
///  - Argon2id           → KAT cruzado com a implementação de REFERÊNCIA PHC (argon2-cffi),
///                         não a libsodium que o app usa. (O vetor do RFC 9106 em si usa p=4 e
///                         chave secreta — parâmetros que a libsodium não expõe; o cruzamento
///                         de implementações cobre o mesmo objetivo.)
///  - Interop Python→Swift → bloco modo 2 gerado por Tools/interop_check.py (PyCA cryptography)
///                         precisa abrir aqui. A direção Swift→Python vive no selftest do script.
final class RFCVectorTests: XCTestCase {

    private func hex(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!); i = j
        }
        return d
    }

    // MARK: - X25519 (RFC 7748)

    /// §5.2, vetor 1: escalar × coordenada-u. Também valida o clamping do escalar (faz parte
    /// da função X25519 e é aplicado pelo CryptoKit ao importar a privada).
    func testX25519_rfc7748_scalarMultVector1() throws {
        let sk = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"))
        let pk = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
        let shared = try sk.sharedSecretFromKeyAgreement(with: pk)
        XCTAssertEqual(shared.withUnsafeBytes { Data($0) },
                       hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"))
    }

    /// §6.1: derivação das públicas de Alice/Bob a partir das privadas do RFC, e o segredo
    /// compartilhado K igual nas duas direções.
    func testX25519_rfc7748_diffieHellmanAliceBob() throws {
        let aliceSK = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        let bobSK = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        XCTAssertEqual(aliceSK.publicKey.rawRepresentation,
                       hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
        XCTAssertEqual(bobSK.publicKey.rawRepresentation,
                       hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
        let k = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        let ab = try aliceSK.sharedSecretFromKeyAgreement(with: bobSK.publicKey)
        let ba = try bobSK.sharedSecretFromKeyAgreement(with: aliceSK.publicKey)
        XCTAssertEqual(ab.withUnsafeBytes { Data($0) }, k)
        XCTAssertEqual(ba.withUnsafeBytes { Data($0) }, k)
    }

    // MARK: - ChaCha20-Poly1305 (RFC 8439 §2.8.2)

    private let rfc8439Key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    private let rfc8439Nonce = "070000004041424344454647"
    private let rfc8439AAD = "50515253c0c1c2c3c4c5c6c7"
    private let rfc8439Plain = "Ladies and Gentlemen of the class of '99: " +
        "If I could offer you only one tip for the future, sunscreen would be it."
    private let rfc8439CT = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
        "3ff4def08e4b7a9de576d26586cec64b6116"
    private let rfc8439Tag = "1ae10b594f09e26a7e902ecbd0600691"

    func testChaCha20Poly1305_rfc8439_seal() throws {
        let box = try ChaChaPoly.seal(Data(rfc8439Plain.utf8),
                                      using: SymmetricKey(data: hex(rfc8439Key)),
                                      nonce: ChaChaPoly.Nonce(data: hex(rfc8439Nonce)),
                                      authenticating: hex(rfc8439AAD))
        XCTAssertEqual(box.ciphertext, hex(rfc8439CT))
        XCTAssertEqual(box.tag, hex(rfc8439Tag))
    }

    func testChaCha20Poly1305_rfc8439_open_andTamperFails() throws {
        let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: hex(rfc8439Nonce)),
                                           ciphertext: hex(rfc8439CT), tag: hex(rfc8439Tag))
        let key = SymmetricKey(data: hex(rfc8439Key))
        let pt = try ChaChaPoly.open(box, using: key, authenticating: hex(rfc8439AAD))
        XCTAssertEqual(pt, Data(rfc8439Plain.utf8))
        // AAD divergente → autenticação falha (o AAD participa do tag).
        XCTAssertThrowsError(try ChaChaPoly.open(box, using: key, authenticating: Data()))
    }

    // MARK: - HKDF-SHA256 (RFC 5869, Apêndice A)

    func testHKDF_rfc5869_case1() {
        let okm = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(repeating: 0x0b, count: 22)),
            salt: hex("000102030405060708090a0b0c"),
            info: hex("f0f1f2f3f4f5f6f7f8f9"),
            outputByteCount: 42)
        XCTAssertEqual(okm.withUnsafeBytes { Data($0) },
                       hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c" +
                           "5db02d56ecc4c5bf34007208d5b887185865"))
    }

    /// Caso 3: salt e info VAZIOS (salt vazio ⇒ HashLen zeros, conforme o RFC).
    func testHKDF_rfc5869_case3_emptySaltAndInfo() {
        let okm = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(repeating: 0x0b, count: 22)),
            salt: Data(), info: Data(), outputByteCount: 42)
        XCTAssertEqual(okm.withUnsafeBytes { Data($0) },
                       hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879e" +
                           "c3454e5f3c738d2d9d201395faa4b61a96c8"))
    }

    // MARK: - Argon2id (KAT cruzado com a implementação de referência PHC)

    /// Gerado por `Tools/interop_check.py argon2-kat` (argon2-cffi 25.1.0 → phc-winner-argon2),
    /// senha "blkh01e-interop-kat", salt 00..0f, ops=2, mem=64 MiB (faixa interactive, dentro de
    /// `withinSaneBounds`). Se a libsodium e a referência PHC divergissem, este teste falharia.
    func testArgon2id_crossImplementationKAT() throws {
        let key = try KeyDerivation.deriveKey(
            password: "blkh01e-interop-kat",
            salt: Array(hex("000102030405060708090a0b0c0d0e0f")),
            params: KDFParams(opsLimit: 2, memLimit: 67_108_864, algorithm: 1))
        XCTAssertEqual(key.withUnsafeBytes { Data($0) },
                       hex("6446556075da4763878364cb69bfadaf169f5fa0ba36c41a48e666eaee96bcac"))
    }

    // MARK: - Interop Python → Swift (modo 2, X25519)

    /// Bloco gerado por `Tools/interop_check.py` (PyCA `cryptography`, nonce fixo) com chaves
    /// determinísticas: sender_sk = 0x01..0x20, recipient_sk = 0xA0..0xBF. Uma implementação
    /// 100% independente produziu este bloco; o app TEM que abri-lo e identificar o remetente.
    func testX25519Mode2_pythonGeneratedBlock_decryptsAndAuthenticatesSender() throws {
        let block = "BLKH01E.1.QkgwMQECAAECAwQFBgcICQoLifGAM4z1TbU8GoRu7FTSCZohJI9KyR6E8bNoP-xExPbz" +
            "qadem7fqV3gMlvEGA95eGYgaPBb7p2LrQwxbNS1LIkR2nw9DALDTQI_LITSOWSbPkIYgrH4EAR1qpfobCRsQ" +
            "798aNMNName03FLQJhLBzcBhKGGHuomaYRmksavlrtwwAoZazPeqzO6vzwimNjsgLa3e-jU_0hABfeK3MMfK" +
            "VGJrFjfi7cyUIQw4BJvhYsBcvI6WuytxUC6HFn7ljsRYTTswJb8KjxNLqfG5hbXuA-IOSzYGDsayz2sFOw-I" +
            "kBsirDKU-DohEONa6Uq97Syax7pr84ZFvOKWxLXqw8KVULALdDU9xuvkYd7gWmOhyJ0"
        let recipientSK = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
        let senderPK = hex("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c")
        // Um candidato ERRADO na lista não pode abrir nem ser apontado como remetente.
        let decoy = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation

        let out = try SecureMessage.decrypt(block, recipientPrivateKey: recipientSK,
                                            senderCandidates: [decoy, senderPK])
        XCTAssertEqual(String(data: out.plaintext, encoding: .utf8), "interop Python→Swift ✔")
        XCTAssertEqual(out.senderPublicKey, senderPK)
    }
}
