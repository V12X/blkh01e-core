import XCTest
@testable import BlackHoleCore

/// CHUNK DE RELAY v1 (mídia grande fatiada em eventos relay-safe): round-trip fatiar→remontar,
/// vetor de formato congelado, teto honesto (grande demais → vazio) e os limites de memória do
/// reassembler contra entrada hostil/lossy. Headless — zero rede.
final class NostrChunkTests: XCTestCase {

    private let msgId = "0011223344556677"   // 16 hex fixos p/ vetor determinístico

    // MARK: - Fatiar / remontar

    func testRoundTrip_splitThenReassemble() {
        // Bloco maior que a fatia → vira N chunks; remontar devolve o bloco EXATO.
        let block = "BLKH01E.1." + String(repeating: "aB3_", count: 5000)   // 20 KB de corpo
        let chunks = Nostr.chunkize(block: block, msgId: msgId, maxSliceChars: 4096, maxChunks: 64)
        XCTAssertEqual(chunks.count, (block.count + 4095) / 4096)
        XCTAssertGreaterThan(chunks.count, 1)

        var r = Nostr.ChunkReassembler()
        var done: String?
        for c in chunks { if let b = r.accept(c) { done = b } }
        XCTAssertEqual(done, block)
    }

    func testReassemble_outOfOrder_andDuplicates() {
        let block = "BLKH01E.1." + String(repeating: "Zz90", count: 3000)
        var chunks = Nostr.chunkize(block: block, msgId: msgId, maxSliceChars: 2048, maxChunks: 64)
        chunks.reverse()                                   // fora de ordem
        chunks.insert(chunks[0], at: 0)                    // duplicata do primeiro
        var r = Nostr.ChunkReassembler()
        var done: String?
        for c in chunks { if let b = r.accept(c) { done = b } }
        XCTAssertEqual(done, block)                         // remonta certo mesmo assim
    }

    func testSingleEventBlocks_notChunked() {
        // Bloco que cabe na fatia continua indo INTEIRO (não é chunk) — retrocompat v1.
        let small = "BLKH01E.1.SGVsbG8"
        XCTAssertFalse(Nostr.isChunk(small))
        // chunkize com fatia grande devolve 1 elemento (a UI só chama chunkize p/ blocos que não cabem).
        let one = Nostr.chunkize(block: small, msgId: msgId, maxSliceChars: 32_768, maxChunks: 64)
        XCTAssertEqual(one.count, 1)
        XCTAssertTrue(Nostr.isChunk(one[0]))
    }

    // MARK: - Formato congelado

    func testChunkFormat_frozenShape() {
        let chunks = Nostr.chunkize(block: "BLKH01E.1.ABCDEFGH", msgId: msgId, maxSliceChars: 4, maxChunks: 64)
        // "BLKH01E.1.ABCDEFGH" tem 18 chars → 5 fatias de 4 (última com 2).
        XCTAssertEqual(chunks.count, 5)
        XCTAssertEqual(chunks[0], "BHK1|\(msgId)|0|5|BLKH")
        XCTAssertEqual(chunks[4], "BHK1|\(msgId)|4|5|GH")
        // parse casa com o que foi gerado.
        let p = Nostr.parseChunk(chunks[0])
        XCTAssertEqual(p?.msgId, msgId)
        XCTAssertEqual(p?.index, 0); XCTAssertEqual(p?.total, 5); XCTAssertEqual(p?.slice, "BLKH")
    }

    func testParseChunk_rejectsGarbage() {
        XCTAssertNil(Nostr.parseChunk("BLKH01E.1.SGVsbG8"))          // bloco inteiro não é chunk
        XCTAssertNil(Nostr.parseChunk("BHK1|zz|0|1|abc"))            // msgId não-hex
        XCTAssertNil(Nostr.parseChunk("BHK1|\(msgId)|3|2|abc"))      // index ≥ total
        XCTAssertNil(Nostr.parseChunk("BHK1|\(msgId)|0|1|"))         // slice vazia
        XCTAssertNil(Nostr.parseChunk("BHK1|\(msgId)|x|1|abc"))      // index não numérico
    }

    // MARK: - Teto honesto (grande demais)

    func testChunkize_returnsEmptyWhenOverCap() {
        let big = String(repeating: "a", count: 10_000)
        XCTAssertTrue(Nostr.chunkize(block: big, msgId: msgId, maxSliceChars: 100, maxChunks: 64).isEmpty) // 100 > 64
        XCTAssertFalse(Nostr.chunkize(block: big, msgId: msgId, maxSliceChars: 200, maxChunks: 64).isEmpty) // 50 ≤ 64
        XCTAssertTrue(Nostr.chunkize(block: "", msgId: msgId, maxSliceChars: 10, maxChunks: 64).isEmpty)    // vazio
    }

    // MARK: - Limites de memória do reassembler

    func testReassembler_evictsAbandonedPartials() {
        // Mais mensagens parciais que o teto → as mais antigas são despejadas (não crescem sem limite).
        var r = Nostr.ChunkReassembler(maxMessages: 2, maxChunksPerMessage: 8, maxTotalBytes: 1 << 20)
        // 3 mensagens, cada uma com só o chunk 0 de 2 (nenhuma completa).
        for i in 0..<3 {
            let id = String(format: "%016x", i)
            XCTAssertNil(r.accept("BHK1|\(id)|0|2|piece"))
        }
        // A mensagem 0 foi despejada: mandar o 2º chunk dela agora NÃO completa (o 1º sumiu).
        XCTAssertNil(r.accept("BHK1|\(String(format: "%016x", 0))|1|2|piece"))
    }

    func testReassembler_rejectsOverByteCap() {
        var r = Nostr.ChunkReassembler(maxMessages: 4, maxChunksPerMessage: 8, maxTotalBytes: 6)
        XCTAssertNil(r.accept("BHK1|\(msgId)|0|2|abcd"))   // 4 bytes
        XCTAssertNil(r.accept("BHK1|\(msgId)|1|2|efgh"))   // +4 = 8 > 6 → descarta, não completa
    }

    func testReassembler_rejectsOverChunkCap() {
        var r = Nostr.ChunkReassembler(maxMessages: 4, maxChunksPerMessage: 2, maxTotalBytes: 1 << 20)
        XCTAssertNil(r.accept("BHK1|\(msgId)|0|3|x"))      // total 3 > cap 2 → ignora
    }

    func testReassembler_reset() {
        var r = Nostr.ChunkReassembler()
        XCTAssertNil(r.accept("BHK1|\(msgId)|0|2|a"))
        r.reset()
        // Após reset, o 2º chunk sozinho não completa (o parcial foi limpo).
        XCTAssertNil(r.accept("BHK1|\(msgId)|1|2|b"))
    }
}
