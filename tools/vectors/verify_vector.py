"""Verificação independente do vetor de integração v1 (docs/format.md §12).

Reconstrói o envelope a partir da especificação usando implementações independentes
(argon2-cffi para Argon2id e `cryptography` para AES-256-GCM/SHA-256) e compara byte a byte com
`vector_v1.hex`, gerado pelo teste Rust `integration_vector_v1`. Somente dados fictícios.

Uso: python -I tools/vectors/verify_vector.py tools/vectors/vector_v1.hex
"""

import hashlib
import struct
import sys

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def s(text: str) -> bytes:
    b = text.encode("utf-8")
    return struct.pack("<I", len(b)) + b


def seq(start: int, n: int = 16) -> bytes:
    return bytes(range(start, start + n))


PASSWORD = "senha de teste fictícia 🔐 não use".encode("utf-8")
DEK = bytes(range(0x00, 0x20))
SALT = bytes(range(0x20, 0x40))
VAULT_ID = seq(0x40)
REVISION = 1
M, T, P = 65536, 3, 4

payload = b"KVP1" + VAULT_ID + struct.pack("<Q", REVISION)
payload += struct.pack("<HHBB", 5, 20, 1, 0)
payload += struct.pack("<I", 1)
payload += seq(0x50) + struct.pack("<qq", 1763856000000, 1763856000000) + b"\x01"
for text in ["Exemplo n8n", "https://n8n.exemplo.invalid", "usuario.ficticio", "S3nh@-Fict1cia", "linha 1\nlinha 2"]:
    payload += s(text)
payload += struct.pack("<H", 2) + s("infra") + s("teste")
payload += struct.pack("<H", 1) + seq(0x60) + b"\x01" + s("API key") + s("chave-ficticia-123")

zero_nonce = bytes(12)
header = b"KVLT" + struct.pack("<HHHH", 1, 1, 1, 132) + VAULT_ID + struct.pack("<Q", REVISION)
header += struct.pack("<IIIII", 0x13, M, T, P, 32)
header += struct.pack("<H", 32) + SALT + struct.pack("<H", 12) + zero_nonce + zero_nonce
header += struct.pack("<HH", 16, 1) + struct.pack("<I", 48) + struct.pack("<Q", len(payload) + 16)
assert len(header) == 132

aad_snapshot = struct.pack("<H", 20) + b"KeyVault/snapshot/v1" + header
data_ct = AESGCM(DEK).encrypt(zero_nonce, payload, aad_snapshot)
kek = hash_secret_raw(PASSWORD, SALT, time_cost=T, memory_cost=M, parallelism=P, hash_len=32, type=Type.ID, version=19)
aad_wrap = struct.pack("<H", 16) + b"KeyVault/wrap/v1" + header + hashlib.sha256(data_ct).digest()
wrapped = AESGCM(kek).encrypt(zero_nonce, DEK, aad_wrap)
envelope = header + wrapped + data_ct

expected = bytes.fromhex(open(sys.argv[1], encoding="ascii").read().strip())
print("len", len(envelope), "sha256", hashlib.sha256(envelope).hexdigest())
print("kek", kek.hex())
if envelope != expected:
    for i, (a, b) in enumerate(zip(envelope, expected)):
        if a != b:
            print("primeira diferença no offset", i)
            break
    print("FALHA: envelope independente difere do gerado pelo Rust")
    sys.exit(1)
print("OK: envelope reconstruído independentemente é idêntico ao do Rust")
