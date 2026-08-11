# Política de Segurança — BlackHoleCore / BLKH01E

*(English speakers: security reports in English are very welcome — same channel below.)*

O BLKH01E é um cofre criptografado que roda **100% no aparelho**, sem servidor e sem conta. Este
pacote (`BlackHoleCore`) é o núcleo de criptografia, publicado aberto para ser auditado. Relatos
sobre o núcleo **ou sobre o aplicativo** são bem-vindos pelo mesmo canal.

## Como reportar uma vulnerabilidade

**Não** abra uma _issue_ pública para falhas de segurança. Envie um relato privado para:

- **E-mail:** contato@blkh01e.com
- Assunto sugerido: `SECURITY: <resumo curto>`

Inclua, se possível:

- descrição do problema e do impacto;
- passos para reproduzir (ou prova de conceito);
- versão/commit e, se for no app, modelo de aparelho + versão do iOS;
- se afeta o **núcleo** (este pacote) ou o **aplicativo**.

Se quiser cifrar o relato, peça no e-mail que enviamos uma chave pública.

## O que esperar

- **Confirmação de recebimento:** em até 5 dias úteis.
- **Triagem inicial:** em até 10 dias úteis, com avaliação de severidade.
- **Correção:** prazo conforme severidade e complexidade; manteremos você informado.
- **Crédito:** com seu consentimento, damos crédito ao relator quando a correção sai.

Pedimos um prazo razoável para a correção antes de qualquer divulgação pública.

## Escopo

**No escopo** (o que mais nos interessa):

- Quebra das garantias criptográficas deste núcleo — cofre, mensagens (modos 1/2 e Double
  Ratchet), formatos de fio congelados, backup cifrado.
- Furos na **deniabilidade do cofre falso** (qualquer coisa que distinga o cofre real do falso —
  em disco, em timing, em comportamento).
- Violação das invariantes do [`THREAT-MODEL.md`](THREAT-MODEL.md) §5 (fail-closed, AAD sobre o
  header, custo de KDF uniforme, tetos anti-DoS, zero rede no núcleo).
- No app: vazamento de dados em claro para fora do aparelho, bypass do bloqueio/autenticação,
  corrupção que leve à perda do cofre.

**Fora do escopo** (limites explícitos do modelo — ver [`THREAT-MODEL.md`](THREAT-MODEL.md) §4):

- Ataques que exigem aparelho já comprometido/jailbroken ou malware com root.
- Comprometimento físico com o cofre **já aberto** na tela.
- Engenharia social para a pessoa revelar o próprio código.
- MITM na troca de QR quando o **número de segurança não foi conferido** (a verificação presencial
  é a defesa desenhada).
- Computador quântico contra o X25519 (roadmap: modo 3 = X-Wing, híbrido PQ).
- Zeroização de memória além do que a plataforma (Swift/`Data`) permite.

Itens fora do escopo **não são "não-problemas"** — são fronteiras documentadas. Relatos que mudem
nossa avaliação sobre elas são bem-vindos.

## Verificação independente

Não confie — verifique ([`THREAT-MODEL.md`](THREAT-MODEL.md) §6):

```bash
swift test                               # 276 testes: vetores RFC, fuzzing, propriedades do ratchet
python3 Tools/interop_check.py selftest  # interop independente (PyCA cryptography + argon2-cffi)
```

## Nossos compromissos

- Não acionamos medidas legais contra pesquisa de segurança de boa-fé dentro desta política.
- Não temos servidor nem cópia dos dados dos usuários: por _design_, não podemos entregar o
  conteúdo de ninguém. Um relato que contradiga isso é de altíssima prioridade.
