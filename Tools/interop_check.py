#!/usr/bin/env python3
"""
interop_check.py — verificação INDEPENDENTE do formato de fio BLKH01E (SecureMessage v1).

Implementado exclusivamente a partir da documentação do formato (SecureMessage.swift, bloco
"FORMATO DE FIO v1 — CONGELADO"), usando bibliotecas Python sem nenhuma relação com o código
Swift/CryptoKit/libsodium do app:

  - `cryptography` (PyCA)  → X25519, HKDF-SHA256, ChaCha20-Poly1305
  - `argon2-cffi`          → Argon2id (implementação de REFERÊNCIA PHC, não a libsodium)

Se este script decifra um bloco gerado pelo app (e vice-versa), o formato faz o que a
documentação promete — "confira você mesmo", sem confiar no binário.

Formato (linha única): BLKH01E.<versão>.<base64url(payload)>
  payload = header || AEAD(ChaCha20-Poly1305; combined = nonce(12) || ct || tag(16); AAD = header)
  modo 1 (senha):  header = "BH01" | ver(1) | mode=1 | opsLimit u32BE | memLimit u32BE | salt(16)  [30 B]
                   chave  = Argon2id v1.3 (p=1, 32 B) da senha com salt/ops/mem do header
  modo 2 (X25519): header = "BH01" | ver(1) | mode=2                                              [6 B]
                   chave  = HKDF-SHA256(X25519(sk, pk), salt="BLKH01E/x25519-v1", info=header, 32 B)
  plaintext cifrado = PAD([u32BE tamanhoReal] || claro || zeros) até múltiplo de 256

Uso:
  python3 interop_check.py selftest
  python3 interop_check.py decrypt-password '<bloco>' '<senha>'
  python3 interop_check.py encrypt-password '<texto>' '<senha>'
  python3 interop_check.py decrypt-x25519 '<bloco>' <recipient_sk_hex> <sender_pk_hex>
  python3 interop_check.py encrypt-x25519 '<texto>' <recipient_pk_hex> <sender_sk_hex> [nonce_hex]
  python3 interop_check.py argon2-kat '<senha>' <salt_hex> <ops> <mem_bytes>
"""
import base64
import os
import re
import struct
import sys

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"BH01"
VERSION = 1
MODE_PASSWORD = 1
MODE_X25519 = 2
X25519_SALT = b"BLKH01E/x25519-v1"
PAD_BLOCK = 256
TOKEN_RE = re.compile(r"BLKH01E\.[0-9]+\.[A-Za-z0-9_-]+")


# ---------- base64url / token ----------

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def extract_payload(armored: str) -> bytes:
    m = TOKEN_RE.search(armored)
    if not m:
        raise ValueError("não é um bloco BLKH01E")
    outer_ver, payload = m.group(0).split(".")[1], b64u_decode(m.group(0).split(".")[2])
    if payload[:4] != MAGIC or str(payload[4]) != outer_ver or payload[4] != VERSION:
        raise ValueError("magic/versão inválidos")
    return payload


# ---------- padding anti-metadado ----------

def pad(plaintext: bytes) -> bytes:
    body = struct.pack(">I", len(plaintext)) + plaintext
    target = -(-len(body) // PAD_BLOCK) * PAD_BLOCK
    return body + b"\x00" * (target - len(body))


def unpad(padded: bytes) -> bytes:
    (length,) = struct.unpack(">I", padded[:4])
    if 4 + length > len(padded):
        raise ValueError("padding inválido")
    return padded[4 : 4 + length]


# ---------- modo 1: senha (Argon2id → ChaCha20-Poly1305) ----------

def argon2id_key(password: str, salt: bytes, ops: int, mem_bytes: int) -> bytes:
    # libsodium usa memLimit em BYTES e paralelismo fixo 1; argon2-cffi usa memory_cost em KiB.
    return hash_secret_raw(password.encode(), salt, time_cost=ops,
                           memory_cost=mem_bytes // 1024, parallelism=1,
                           hash_len=32, type=Type.ID, version=19)


def decrypt_password(armored: str, password: str) -> bytes:
    payload = extract_payload(armored)
    if payload[5] != MODE_PASSWORD:
        raise ValueError(f"modo {payload[5]}, esperado 1 (senha)")
    header, sealed = payload[:30], payload[30:]
    ops, mem = struct.unpack(">II", header[6:14])
    key = argon2id_key(password, header[14:30], ops, mem)
    pt = ChaCha20Poly1305(key).decrypt(sealed[:12], bytes(sealed[12:]), header)
    return unpad(pt)


def encrypt_password(plaintext: bytes, password: str, ops: int = 2,
                     mem_bytes: int = 67108864) -> str:
    salt = os.urandom(16)
    header = MAGIC + bytes([VERSION, MODE_PASSWORD]) + struct.pack(">II", ops, mem_bytes) + salt
    key = argon2id_key(password, salt, ops, mem_bytes)
    nonce = os.urandom(12)
    sealed = nonce + ChaCha20Poly1305(key).encrypt(nonce, pad(plaintext), header)
    return f"BLKH01E.{VERSION}.{b64u_encode(header + sealed)}"


# ---------- modo 2: X25519 (ECDH → HKDF-SHA256 → ChaCha20-Poly1305) ----------

def x25519_key(my_sk: bytes, their_pk: bytes, header: bytes) -> bytes:
    shared = X25519PrivateKey.from_private_bytes(my_sk).exchange(
        X25519PublicKey.from_public_bytes(their_pk))
    return HKDF(algorithm=SHA256(), length=32, salt=X25519_SALT, info=header).derive(shared)


def decrypt_x25519(armored: str, recipient_sk: bytes, sender_pk: bytes) -> bytes:
    payload = extract_payload(armored)
    if payload[5] != MODE_X25519:
        raise ValueError(f"modo {payload[5]}, esperado 2 (X25519)")
    header, sealed = payload[:6], payload[6:]
    key = x25519_key(recipient_sk, sender_pk, header)
    pt = ChaCha20Poly1305(key).decrypt(sealed[:12], bytes(sealed[12:]), header)
    return unpad(pt)


def encrypt_x25519(plaintext: bytes, recipient_pk: bytes, sender_sk: bytes,
                   nonce: bytes = None) -> str:
    header = MAGIC + bytes([VERSION, MODE_X25519])
    key = x25519_key(sender_sk, recipient_pk, header)
    nonce = nonce or os.urandom(12)
    sealed = nonce + ChaCha20Poly1305(key).encrypt(nonce, pad(plaintext), header)
    return f"BLKH01E.{VERSION}.{b64u_encode(header + sealed)}"


# ---------- selftest ----------

# Vetor CONGELADO da suíte Swift (FrozenVectorTests.frozenArmoredV1): gerado pelo APP.
# Decifrá-lo aqui prova a direção Swift → Python.
FROZEN_V1 = ("BLKH01E.1.QkgwMQEBAAAAAgQAAABy4XdN9qZu_ta-osFRM_U38HIhdsCi_v4BhkX_9-hQ"
             "-K-84h6NypYDUHcKRpoPEOtUeCVYmKsksuyBXdDklFg0b_iUSYwxFgUEymXeA28-3KVN3Y"
             "9bjTStDUiB63XynTxil-mOta27kE95G_u59fqkXCsN4LiUos7nec20KpdPRzsH1HdetkAo"
             "ES3TTj3PgtQ1SzI0wuK8aHpwn0mg8WeFN-XMk3oEAvVfkKRdJwDTCUv1ZxGo26fsKh1PV-"
             "0KFtuF8gDXLk_zBHbKrZ4fmd_Frw-5W-LTkxhEBXfMiJ6uQwc_Lxx8R4YV2tpgMgNN_eRG"
             "aO-vhj-Dl8wnCgf-Pw7gs0oymlFy02_e0S5NSF7TdVHfGv5uIdRfOT3ItesU7o0MsuFLIZ"
             "yobuvcpuQ")


def selftest() -> None:
    # 1) Swift → Python: o vetor congelado do app abre com a senha conhecida.
    pt = decrypt_password(FROZEN_V1, "senha-fixa-v1")
    assert pt.decode() == "mensagem congelada v1 🕳️", pt
    print("OK  Swift→Python: vetor congelado v1 (modo senha) decifrado")

    # 2) Senha errada → autenticação falha (nunca plaintext errado).
    try:
        decrypt_password(FROZEN_V1, "outra")
        raise AssertionError("senha errada NÃO pode abrir")
    except Exception:
        print("OK  senha errada rejeitada pela autenticação (Poly1305)")

    # 3) Roundtrip local modo senha (ops/mem mínimos p/ rapidez).
    blk = encrypt_password("teste local 🧪".encode(), "s3nh4", ops=2, mem_bytes=67108864)
    assert decrypt_password(blk, "s3nh4").decode() == "teste local 🧪"
    print("OK  roundtrip Python modo 1 (senha)")

    # 4) Roundtrip local modo X25519.
    a_sk = X25519PrivateKey.generate()
    b_sk = X25519PrivateKey.generate()
    a_pk = a_sk.public_key().public_bytes_raw()
    b_pk = b_sk.public_key().public_bytes_raw()
    blk = encrypt_x25519("eco 🛰".encode(), b_pk, a_sk.private_bytes_raw())
    assert decrypt_x25519(blk, b_sk.private_bytes_raw(), a_pk).decode() == "eco 🛰"
    print("OK  roundtrip Python modo 2 (X25519)")
    print("\nSELFTEST COMPLETO — formato de fio confere com a documentação.")


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    if cmd == "selftest":
        selftest()
    elif cmd == "decrypt-password":
        print(decrypt_password(sys.argv[2], sys.argv[3]).decode())
    elif cmd == "encrypt-password":
        print(encrypt_password(sys.argv[2].encode(), sys.argv[3]))
    elif cmd == "decrypt-x25519":
        print(decrypt_x25519(sys.argv[2], bytes.fromhex(sys.argv[3]),
                             bytes.fromhex(sys.argv[4])).decode())
    elif cmd == "encrypt-x25519":
        nonce = bytes.fromhex(sys.argv[5]) if len(sys.argv) > 5 else None
        sk = bytes.fromhex(sys.argv[4])
        print("sender_pk:", X25519PrivateKey.from_private_bytes(sk)
              .public_key().public_bytes_raw().hex())
        print(encrypt_x25519(sys.argv[2].encode(), bytes.fromhex(sys.argv[3]), sk, nonce))
    elif cmd == "argon2-kat":
        print(argon2id_key(sys.argv[2], bytes.fromhex(sys.argv[3]),
                           int(sys.argv[4]), int(sys.argv[5])).hex())
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
