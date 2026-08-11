# BlackHoleCore

Núcleo de criptografia do **BLKH01E (Black Hole)** — um cofre criptografado que roda 100% no
aparelho, sem servidor e sem conta. Este pacote é a parte **auditável**: as primitivas e o formato
de fio que cifram o cofre e as mensagens. A regra de ouro é superfície mínima — só cripto auditada.

> Publicado aberto para que a promessa "nem nós vemos" possa ser **verificada, não apenas
> acreditada**. *Don't trust — verify.*

## O que tem aqui

- **Cofre em repouso:** Argon2id (libsodium) → ChaCha20-Poly1305 (CryptoKit), com envelope
  versionado e parâmetros de KDF persistidos.
- **Mensagens:** identidades **X25519** trocadas por QR; conversa com **Double Ratchet** (à la
  Signal, sem servidor) — forward secrecy e recuperação pós-comprometimento.
- **Anti-metadado:** padding com quantização de 256 bytes dentro do AEAD.
- **Deniabilidade:** suporte a cofre falso com custo de KDF uniforme (sem oráculo de timing).

Detalhes de segurança e limites honestos no [`THREAT-MODEL.md`](THREAT-MODEL.md); como reportar
falhas no [`SECURITY.md`](SECURITY.md).

## Verifique você mesmo

```bash
swift test                              # 276 testes (vetores RFC, fuzzing, propriedades do ratchet)
python3 Tools/interop_check.py selftest # interop independente em Python (PyCA + argon2-cffi)
```

- **Vetores de referência (RFC):** `Tests/BlackHoleCoreTests/RFCVectorTests.swift` — X25519
  (RFC 7748), ChaCha20-Poly1305 (RFC 8439), HKDF-SHA256 (RFC 5869), Argon2id (KAT cruzado).
- **Interop independente:** `Tools/interop_check.py` — implementação Python do formato `BLKH01E.1`
  escrita só a partir da documentação; decifra blocos do app e vice-versa.
- **Fuzzing + propriedades:** `Tests/BlackHoleCoreTests/FuzzTests.swift` e `RatchetPropertyTests.swift`.

## Dependências

- [swift-sodium](https://github.com/jedisct1/swift-sodium) — Argon2id (libsodium). Licença ISC.
- [secp256k1.swift](https://github.com/GigaBitcoin/secp256k1.swift) — Schnorr para eventos Nostr do
  transporte ao vivo (não cifra mensagens). Licença MIT.
- CryptoKit (Apple) — X25519, ChaCha20-Poly1305, HKDF, HMAC, SHA-256.

## Licença

**GNU GPL v3.0** — ver [`LICENSE`](LICENSE).

Copyright © BLKH01E. Todos os direitos reservados sobre a obra original.

O detentor do copyright (BLKH01E) **retém todos os direitos** e disponibiliza também este código
sob termos proprietários para uso no aplicativo BLKH01E fechado. A licença GPL vale para
**terceiros**: quem incorporar o BlackHoleCore precisa liberar o trabalho derivado sob GPL-3.0.
Para uso comercial sob outros termos, fale com contato@blkh01e.com.
