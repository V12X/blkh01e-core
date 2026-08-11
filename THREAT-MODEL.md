# Modelo de Ameaça — BlackHoleCore

*(English speakers: this is the threat model for BLKH01E's crypto core. Reports and questions in
English are welcome — see [SECURITY.md](SECURITY.md).)*

Este documento diz **o que o sistema protege, contra quem, e — com a mesma clareza — o que ele NÃO
protege**. Abrir o código sem isto convida mal-entendido nos dois sentidos: superestimar e
subestimar a proteção.

Princípio de projeto: **Kerckhoffs** — tudo aqui continua seguro com o adversário conhecendo o
código, os formatos e os algoritmos. A única coisa secreta são as chaves.

---

## 1. Arquitetura em uma tela

- **Sem servidor, sem conta.** Não existe backend do desenvolvedor. Todo dado vive no aparelho,
  cifrado. Não há o que intimar, vazar ou hackear do nosso lado.
- **Cofre local:** código numérico (mín. 8 dígitos, + palavra-chave opcional) → **Argon2id**
  (libsodium, custo *moderate* uniforme) → chave-mestra (MK) → **ChaCha20-Poly1305** em tudo.
  Chave por arquivo (FEK) embrulhada sob a MK; **apagar = destruir a chave**.
- **Cofre falso (deniability):** um segundo código abre um cofre à parte. Os *slots* do envelope
  são indistinguíveis, e **todo** caminho de abertura (real, falso, senha errada, envelope
  malformado) paga o **mesmo custo de KDF** — sem oráculo de timing. A negação é criptográfica,
  não obscuridade.
- **Mensagens** (formato de fio congelado `BLKH01E.…`):
  - **modo 1 (senha):** Argon2id → ChaCha20-Poly1305. Simétrico puro — já resistente a quântico.
  - **modo 2 (X25519):** ECDH + HKDF-SHA256 → ChaCha20-Poly1305; autentica o remetente sem
    expor a pública dele no bloco.
  - **conversas (Double Ratchet):** X25519 + HKDF/HMAC-SHA256 + ChaCha20-Poly1305, à la Signal,
    **sem servidor** — bootstrap nas identidades trocadas por QR presencial.
  - **Padding anti-metadado** em todos: o tamanho só revela o balde de 256 bytes.
- **Transporte-agnóstico:** o bloco cifrado viaja por qualquer canal (WhatsApp, AirDrop, relays
  públicos Nostr, rede local). O canal é considerado **hostil por padrão**.
- **Backup:** arquivo único cifrado localmente pela frase de recuperação (12 palavras) antes de
  tocar o iCloud do usuário. A Apple recebe só ciphertext.

## 2. Ativos protegidos

1. Conteúdo do cofre (arquivos, notas, senhas, seeds de carteira).
2. Conteúdo das mensagens e a **relação remetente↔destinatário** dentro do bloco.
3. A **existência do cofre real** perante quem obteve o código do cofre falso.
4. Chaves de identidade e estados de sessão do ratchet (vivem sob a MK, como qualquer conteúdo).

## 3. Adversários considerados (em escopo)

| Adversário | Resposta do design |
|---|---|
| **Ladrão/perito com o aparelho, sem o código** | Argon2id (custo moderate) + palavra-chave opcional; backoff progressivo; opção de destruir após N erros; dados = ciphertext ChaCha20-Poly1305 |
| **Coação com entrega de código** | Cofre falso: slots indistinguíveis, custo uniforme, nada no disco ou no timing denuncia o cofre real |
| **Provedor de nuvem / intimação legal** | Não há servidor nosso; backup no iCloud é ciphertext sob a frase do usuário; a Apple não tem a chave |
| **Adversário de rede no transporte das mensagens** | AEAD fim-a-fim; AAD autentica header (anti-downgrade/adulteração); padding esconde comprimento; modo 2 não expõe a pública do remetente no bloco |
| **Remetente de blocos maliciosos (entrada hostil)** | Parsers fail-closed (fuzz exaustivo na suíte); tetos anti-DoS (tamanho, custo de KDF do header, gap de ratchet ≤ 100) |
| **Comprometimento PASSIVO do estado do ratchet** | Forward secrecy (o estado atual não reabre o passado) e **healing** após um round-trip completo — janela documentada na suíte (`RatchetPropertyTests`) |

## 4. Fora do escopo (com a mesma honestidade)

- **Aparelho comprometido.** Malware com root/jailbreak, teclado malicioso ou iOS adulterado leem
  o que o usuário lê. Com o cofre ABERTO, chaves e claros estão na RAM. Nenhum app resolve isso.
- **A outra ponta.** Print, câmera apontada pra tela, ou o telefone do contato desbloqueado nas
  mãos erradas. Cifra protege o trânsito e o repouso, não o destino.
- **Troca de QR não verificada (MITM presencial).** Se você escaneia o QR de um impostor, cifra
  para o impostor. O app oferece o **número de segurança** para conferir fora de banda — a
  verificação é o que fecha esse buraco, e é responsabilidade do usuário.
- **Computador quântico vs. X25519.** O acordo de chave dos modos 2/ratchet não é pós-quântico
  (risco "colher agora, decifrar depois"). O modo 1 (simétrico) já resiste. Roteiro: modo 3 =
  X-Wing (híbrido PQ), previsto no formato versionado sem quebrar v1.
- **Análise de tráfego além do comprimento.** Padding esconde o tamanho exato, não o horário,
  a frequência nem os metadados do canal escolhido (ex.: WhatsApp sabe que você enviou *algo*).
- **Zeroização completa de memória.** `Data`/`String` do Swift podem deixar cópias na RAM que não
  conseguimos zerar (limitação da plataforma). Buffers da libsodium são zerados onde possível.
  Mitigação sistêmica: auto-bloqueio, tela-para-baixo, veil de privacidade.
- **Metadados do backup.** O arquivo `.blkh01e` no iCloud revela existência, tamanho aproximado e
  datas — não o conteúdo.
- **Chaves puladas do ratchet.** Mensagens fora de ordem mantêm chaves derivadas em estoque
  (máx. 100, FIFO, sob a MK) até chegarem — janela deliberada de usabilidade, com teto testado.

## 5. Invariantes (contratos congelados e testados)

1. **Fail-closed:** qualquer falha (senha errada, adulteração, formato) → erro uniforme, nunca
   plaintext parcial/errado. Byte-flip em **toda** posição dos blocos falha (suíte de fuzz).
2. **Formato de fio v1 congelado:** mudanças exigem bump de versão com migração; vetores
   congelados + vetores RFC + interop Python independente na suíte (276 testes).
3. **AAD cobre o header inteiro** (modo, versão, custo de KDF): downgrade e adulteração de
   parâmetros são fechados criptograficamente.
4. **Custo de KDF uniforme** em todo caminho de abertura do cofre (real/falso/erro) — sem oráculo.
5. **Anti-DoS:** custo de Argon2id lido de header hostil é TETADO no padrão; tamanhos e gaps têm
   limites duros.
6. **Zero telemetria.** O núcleo não faz rede. O app só toca a rede nos transportes que o usuário
   escolhe (relays, rede local) e no iCloud do próprio usuário.

## 6. Verifique você mesmo

- `swift test` — 276 testes: vetores RFC 7748/8439/5869, KAT Argon2id cruzado com a referência
  PHC, fuzz determinístico, propriedades do ratchet (FS, healing pós-comprometimento, teto FIFO
  das chaves puladas, fronteiras e quantização do padding).
- `python3 Tools/interop_check.py selftest` — implementação Python 100% independente (PyCA
  `cryptography` + `argon2-cffi`) decifra blocos gerados pelo app, e o app decifra os dela.
- Histórico do repositório varrido com gitleaks (config em `.gitleaks.toml`): sem segredos.
- Encontrou algo? [SECURITY.md](SECURITY.md).