// swift-tools-version: 5.10
import PackageDescription

// BlackHoleCore — núcleo de criptografia do Black Hole System (BLKH01E).
// Package independente e testável de forma headless (`swift test`), sem Xcode/simulador.
// Regra de ouro: superfície de cripto mínima. Só primitivas auditadas:
//   - Argon2id (libsodium, via swift-sodium) para esticar a senha.
//   - ChaCha20-Poly1305 (CryptoKit, auditado pela Apple) para todo AEAD.
let package = Package(
    name: "BlackHoleCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "BlackHoleCore", targets: ["BlackHoleCore"]),
    ],
    dependencies: [
        // Pin EXATO (cadeia de suprimento): num núcleo de cripto, dependência não muda sem commit.
        // Bump deliberado a cada upgrade, com re-teste da suíte (KAT do Argon2id pega divergência).
        .package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0"),
        // secp256k1/schnorr (libsecp256k1 da Bitcoin Core) — NÃO existe no CryptoKit e é EXIGIDO
        // pelo Nostr para assinar eventos do transporte da sessão ao vivo. Uso restrito ao módulo
        // Nostr; a cripto das MENSAGENS continua sendo só CryptoKit + libsodium. Versão pinada
        // (dependência sensível): o produto é `P256K`, com o trait `schnorrsig` ligado por padrão.
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", exact: "0.23.2"),
    ],
    targets: [
        .target(
            name: "BlackHoleCore",
            dependencies: [
                .product(name: "Sodium", package: "swift-sodium"),
                .product(name: "P256K", package: "secp256k1.swift"),
            ]
        ),
        .testTarget(
            name: "BlackHoleCoreTests",
            dependencies: ["BlackHoleCore"]
        ),
    ]
)
