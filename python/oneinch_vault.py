#!/usr/bin/env python3
"""
Portable vault format for re-encrypting extracted 1inch wallets.

Uses only standard, well-audited crypto (libsodium / pynacl):
  - Argon2id KDF (t=4, m=256MiB, p=1, hashLen=32) — stronger than 1inch defaults
  - XChaCha20-Poly1305 AEAD (libsodium standard, with real tag verification)

Blob format (binary, little-endian):
    bytes 0..8   magic "1ivault\\0"        (8 bytes)
    bytes 8      version                    (1 byte, currently 1)
    bytes 9..12  reserved                   (3 bytes, zero)
    bytes 12..16 time_cost (u32 LE)
    bytes 16..20 memory_cost_KiB (u32 LE)
    bytes 20..24 parallelism (u32 LE)
    bytes 24..56 argon2id salt              (32 bytes)
    bytes 56..80 XChaCha20 nonce            (24 bytes)
    bytes 80..N  XChaCha20-Poly1305 ciphertext + 16-byte tag

Commands:
    encrypt <plaintext> -P <password> -o <vault.bin>
    decrypt <vault.bin> -P <password> -o <plaintext>

Dependencies: pip install argon2-cffi pynacl
"""
import argparse
import os
import struct
import sys
from pathlib import Path

from argon2.low_level import hash_secret_raw, Type
import nacl.bindings as nb

MAGIC = b"1ivault\x00"
VERSION = 1
SALT_LEN = 32
NONCE_LEN = 24
TAG_LEN = 16
KEY_LEN = 32
# layout: 8 magic + 1 ver + 3 rsv + 4+4+4 params + 32 salt + 24 nonce = 80
HEADER_LEN = 80

DEFAULT_T = 4
DEFAULT_M = 262144  # KiB = 256 MiB
DEFAULT_P = 1


def derive_key(password: bytes, salt: bytes, t: int, m: int, p: int) -> bytes:
    return hash_secret_raw(
        secret=password, salt=salt, time_cost=t, memory_cost=m,
        parallelism=p, hash_len=KEY_LEN, type=Type.ID,
    )


def encrypt(plaintext: bytes, password: bytes, *, t=DEFAULT_T, m=DEFAULT_M, p=DEFAULT_P) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt, t, m, p)
    ct = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(
        message=plaintext, aad=None, nonce=nonce, key=key,
    )
    header = (
        MAGIC
        + bytes([VERSION])
        + b"\x00\x00\x00"
        + struct.pack("<III", t, m, p)
        + salt
        + nonce
    )
    if len(header) != HEADER_LEN:
        raise RuntimeError(f"internal: header length {len(header)} != {HEADER_LEN}")
    return header + ct


def decrypt(blob: bytes, password: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("bad magic — not a 1ivault file")
    version = blob[8]
    if version != VERSION:
        raise ValueError(f"unsupported vault version {version}")
    if len(blob) < HEADER_LEN + TAG_LEN:
        raise ValueError("blob too short")
    t, m, p = struct.unpack_from("<III", blob, 12)
    # Sanity-bound KDF params — defend against a maliciously-crafted vault that
    # sets memory_cost=4GiB to DoS the machine.
    if not (1 <= t <= 16):
        raise ValueError(f"unreasonable t_cost={t}")
    if not (1024 <= m <= 1 << 22):  # 1 MiB .. 4 GiB
        raise ValueError(f"unreasonable memory_cost={m} KiB")
    if not (1 <= p <= 16):
        raise ValueError(f"unreasonable parallelism={p}")
    salt = blob[24:56]
    nonce = blob[56:80]
    ct = blob[80:]
    key = derive_key(password, salt, t, m, p)
    try:
        return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext=ct, aad=None, nonce=nonce, key=key,
        )
    except Exception as e:
        raise ValueError("decryption failed (wrong password or corrupt blob)") from e


def main():
    ap = argparse.ArgumentParser(description="1inch wallet vault (portable re-encryption)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="encrypt a plaintext file")
    enc.add_argument("input")
    enc.add_argument("-P", "--password", default=None,
                     help="passphrase (omit to read from $ONEINCH_VAULT_PASSWORD or prompt)")
    enc.add_argument("-o", "--output", required=True)
    enc.add_argument("-t", "--time-cost", type=int, default=DEFAULT_T)
    enc.add_argument("-m", "--memory-kib", type=int, default=DEFAULT_M)
    enc.add_argument("-p", "--parallelism", type=int, default=DEFAULT_P)

    dec = sub.add_parser("decrypt", help="decrypt a vault file")
    dec.add_argument("input")
    dec.add_argument("-P", "--password", default=None,
                     help="passphrase (omit to read from $ONEINCH_VAULT_PASSWORD or prompt)")
    dec.add_argument("-o", "--output", required=True)

    args = ap.parse_args()

    import getpass
    def read_pw(label):
        if args.password is not None:
            print(f"[!] warning: {label} passphrase on command line is visible via ps/history",
                  file=sys.stderr)
            return args.password.encode("utf-8")
        if os.environ.get("ONEINCH_VAULT_PASSWORD"):
            return os.environ["ONEINCH_VAULT_PASSWORD"].encode("utf-8")
        return getpass.getpass(f"{label} passphrase: ").encode("utf-8")

    def write_secure(path: Path, data: bytes):
        if path.exists():
            ans = input(f"[?] {path} exists. Overwrite? [y/N] ")
            if ans.strip().lower() != "y":
                print("[!] aborted.")
                sys.exit(4)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

    if args.cmd == "encrypt":
        pt = Path(args.input).read_bytes()
        blob = encrypt(
            pt, read_pw("encrypt"),
            t=args.time_cost, m=args.memory_kib, p=args.parallelism,
        )
        out = Path(args.output)
        write_secure(out, blob)
        print(f"[+] wrote {out} ({len(blob)} bytes, chmod 600)")
        print(f"    t={args.time_cost}  m={args.memory_kib}KiB  p={args.parallelism}")
    else:
        blob = Path(args.input).read_bytes()
        pt = decrypt(blob, read_pw("decrypt"))
        out = Path(args.output)
        write_secure(out, pt)
        print(f"[+] wrote {out} ({len(pt)} bytes plaintext, chmod 600)")


if __name__ == "__main__":
    main()
