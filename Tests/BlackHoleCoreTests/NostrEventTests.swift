import XCTest
import CryptoKit
import P256K
@testable import BlackHoleCore

/// Evento Nostr (NIP-01) do transporte da sessão ao vivo: id canônico determinístico, assinatura
/// schnorr que fecha o round-trip, e parse dos quadros do relay. Headless — zero rede.
final class NostrEventTests: XCTestCase {

    private let pubkey = String(repeating: "00", count: 32)   // 64 hex fixos, p/ vetor determinístico
    private let mailbox = "e6949375c29e8b4616387be3030c4cbe5fddb39e902f335beb9b25efceab145e"
    private let createdAt: Int64 = 1_760_000_000
    private var tags: [[String]] { [["t", mailbox]] }
    private let content = "BLKH01E.1.SGVsbG8"

    // MARK: - id canônico (vetor congelado)

    func testEventID_deterministic() {
        let a = Nostr.eventID(pubkey: pubkey, createdAt: createdAt, kind: Nostr.liveKind, tags: tags, content: content)
        let b = Nostr.eventID(pubkey: pubkey, createdAt: createdAt, kind: Nostr.liveKind, tags: tags, content: content)
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.count, 64)
    }

    func testEventID_frozenVector() {
        let id = Nostr.eventID(pubkey: pubkey, createdAt: createdAt, kind: Nostr.liveKind, tags: tags, content: content)
        // CONGELADO: muda = a serialização canônica / id mudou (quebra interop com quem já publica).
        XCTAssertEqual(id, "1f12226dacf5b0038a3ae4939d699c5db7c0ec469871f6f154a3d4a0abf0c35a")
    }

    func testCanonical_shape_andEscaping() {
        let canon = Nostr.canonical(pubkey: pubkey, createdAt: createdAt, kind: Nostr.liveKind,
                                    tags: tags, content: "a\"b\nc")
        XCTAssertTrue(canon.hasPrefix("[0,\"\(pubkey)\",\(createdAt),\(Nostr.liveKind),[[\"t\",\"\(mailbox)\"]],"))
        XCTAssertTrue(canon.hasSuffix("\"a\\\"b\\nc\"]"))   // aspas e quebra escapadas; sem espaços
    }

    // MARK: - assinar → verificar

    func testSignThenVerify_roundTrip() throws {
        let key = try P256K.Schnorr.PrivateKey(dataRepresentation: Data(repeating: 0x42, count: 32))
        guard let ev = Nostr.sign(kind: Nostr.liveKind, tags: tags, content: content,
                                  createdAt: createdAt, privateKey: key) else {
            return XCTFail("sign devolveu nil")
        }
        // id bate com o cálculo independente.
        let pk = Nostr.hex(Data(key.xonly.bytes))
        XCTAssertEqual(ev.id, Nostr.eventID(pubkey: pk, createdAt: createdAt, kind: Nostr.liveKind,
                                            tags: tags, content: content))
        // A assinatura embutida no JSON valida contra o id e a pública.
        let sig = extract(ev.json, "sig")
        XCTAssertTrue(Nostr.verify(id: ev.id, pubkeyHex: pk, sigHex: sig))
        // id adulterado → não valida.
        var bad = Array(ev.id); bad.swapAt(0, 1)
        XCTAssertFalse(Nostr.verify(id: String(bad), pubkeyHex: pk, sigHex: sig))
    }

    // MARK: - quadros do relay

    func testFrames_shape() {
        guard let ev = Nostr.signEphemeral(kind: Nostr.liveKind, tags: tags, content: content, createdAt: createdAt) else {
            return XCTFail("signEphemeral nil")
        }
        XCTAssertTrue(Nostr.publishFrame(ev).hasPrefix("[\"EVENT\",{"))
        let req = Nostr.reqFrame(subID: "s1", mailboxes: [mailbox, "ff"], since: 123, limit: 200)
        XCTAssertTrue(req.contains("\"kinds\":[\(Nostr.liveKind)]"))
        XCTAssertTrue(req.contains("\"#t\":[\"\(mailbox)\",\"ff\"]"))
        XCTAssertTrue(req.contains("\"since\":123"))
        XCTAssertTrue(req.contains("\"limit\":200"))
        XCTAssertEqual(Nostr.closeFrame(subID: "s1"), "[\"CLOSE\",\"s1\"]")
    }

    func testParseFrame_variants() {
        // Evento recebido: ["EVENT","sub",{...}] → extrai id + content.
        guard let ev = Nostr.signEphemeral(kind: Nostr.liveKind, tags: tags, content: content, createdAt: createdAt) else {
            return XCTFail("nil")
        }
        let incoming = "[\"EVENT\",\"sub9\",\(ev.json)]"
        XCTAssertEqual(Nostr.parseFrame(incoming), .event(sub: "sub9", id: ev.id, content: content))
        XCTAssertEqual(Nostr.parseFrame("[\"EOSE\",\"sub9\"]"), .eose(sub: "sub9"))
        XCTAssertEqual(Nostr.parseFrame("[\"OK\",\"\(ev.id)\",true,\"\"]"), .ok(id: ev.id, accepted: true))
        XCTAssertEqual(Nostr.parseFrame("[\"NOTICE\",\"rate limited\"]"), .notice("rate limited"))
        XCTAssertNil(Nostr.parseFrame("não é json"))
        XCTAssertEqual(Nostr.parseFrame("[\"WEIRD\"]"), .other)
    }

    /// Extrai um campo string simples do JSON do evento (helper de teste, não do produto).
    private func extract(_ json: String, _ key: String) -> String {
        let data = json.data(using: .utf8)!
        let obj = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
        return obj[key] as! String
    }
}
