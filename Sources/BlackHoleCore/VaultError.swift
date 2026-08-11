import Foundation

/// Erros do núcleo.
///
/// IMPORTANTE (invariante de indistinguibilidade): `open()` NUNCA revela qual fator falhou.
/// Senha errada, cofre inexistente, fator-dispositivo errado e cofre crypto-shredado colapsam
/// TODOS em `.wrongPasswordOrNoVault`, para o atacante não distinguir os casos. Os demais erros
/// são de `create()`/uso interno e nunca escapam de `open()`.
public enum VaultError: Error, Equatable {
    case wrongPasswordOrNoVault
    case deviceAuthUnavailable  // Face ID cancelado / enclave indisponível (evento de UX, não senha)
    case emptyPassword          // create(): senha vazia rejeitada
    case randomFailure          // falha de RNG (fail-closed)
    case keyDerivationFailed
    case corrupted              // adulteração detectada DENTRO de um cofre já aberto
    case sessionClosed          // sessão travada (reautenticável) — distinto de destruição
    case shredded               // reservado para destruição real de chave
    case invalidArgument        // entrada inválida na camada de gavetas (id vazio/duplicado, createdAt não-finito)
}
