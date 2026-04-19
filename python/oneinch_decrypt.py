#!/usr/bin/env python3
"""
Pure Python standalone 1inch Wallet backup decryptor (v3 format).

Reverse-engineered algorithm:
    1. Parse blob header: magic "1inchbackup" (11B) + version (2B, int16 LE)
    2. Read Argon2id params from blob:
         salt       = blob[13:45]   (32 bytes, random per-backup)
         t_cost     = blob[45:49]   (u32 LE)
         m_cost_KiB = blob[49:53]   (u32 LE)
         parallelism= blob[53:57]   (u32 LE)
         unknown_32 = blob[57:89]   (32B, per-backup random — unused in decryption)
         nonce_24   = blob[89:113]  (24B XChaCha20 nonce)
         ct+tag     = blob[113:]    (ciphertext + 16-byte Poly1305 tag)
    3. KEK = Argon2id(password, salt, t, m, p, hashLen=32)
    4. A   = SHA3-256 iterated 30,001 times on KEK
    5. subkey = HChaCha20(A, nonce_24[:16])
    6. plaintext = ChaCha20-classic(subkey, nonce_24[16:24], ct, counter=1)
       (Poly1305 tag construction is non-standard — not verified in this tool)

Usage:
    python3 oneinch_decrypt.py <backup.1inch> <password>

Dependencies:
    pip install argon2-cffi

Author: reverse-engineered for wallet recovery. Use only on your own backups.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

from argon2.low_level import hash_secret_raw, Type

MAGIC = b"1inchbackup"
SHA3_ITER = 30001


def rotl32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = rotl32(s[b], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20 subkey derivation (RFC draft-irtf-cfrg-xchacha)."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(state, 0, 4, 8, 12); _qr(state, 1, 5, 9, 13)
        _qr(state, 2, 6, 10, 14); _qr(state, 3, 7, 11, 15)
        _qr(state, 0, 5, 10, 15); _qr(state, 1, 6, 11, 12)
        _qr(state, 2, 7, 8, 13); _qr(state, 3, 4, 9, 14)
    return b"".join(struct.pack("<I", w) for w in state[0:4] + state[12:16])


def chacha20_block(key: bytes, nonce8: bytes, counter: int) -> bytes:
    """ChaCha20 classic (8B nonce, 8B counter)."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<2I", counter.to_bytes(8, "little")))
    state += list(struct.unpack("<2I", nonce8))
    ws = state[:]
    for _ in range(10):
        _qr(ws, 0, 4, 8, 12); _qr(ws, 1, 5, 9, 13)
        _qr(ws, 2, 6, 10, 14); _qr(ws, 3, 7, 11, 15)
        _qr(ws, 0, 5, 10, 15); _qr(ws, 1, 6, 11, 12)
        _qr(ws, 2, 7, 8, 13); _qr(ws, 3, 4, 9, 14)
    return b"".join(
        struct.pack("<I", (ws[i] + state[i]) & 0xFFFFFFFF) for i in range(16)
    )


def chacha20_xor(key: bytes, nonce8: bytes, data: bytes, counter_start: int = 1) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, nonce8, counter_start + i // 64)
        chunk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def derive_keys(password: bytes, blob: bytes) -> bytes:
    """Run the 1inch KDF pipeline. Returns the 32-byte XChaCha20 key."""
    if not blob.startswith(MAGIC):
        raise ValueError(f"bad magic (expected {MAGIC!r})")
    version = struct.unpack_from("<H", blob, len(MAGIC))[0]
    if version != 3:
        raise ValueError(f"unsupported version {version} (only v3 supported)")

    salt = blob[13:45]
    t_cost = struct.unpack_from("<I", blob, 45)[0]
    m_cost = struct.unpack_from("<I", blob, 49)[0]
    parallelism = struct.unpack_from("<I", blob, 53)[0]

    kek = hash_secret_raw(
        secret=password, salt=salt, time_cost=t_cost, memory_cost=m_cost,
        parallelism=parallelism, hash_len=32, type=Type.ID,
    )

    a = kek
    for _ in range(SHA3_ITER):
        a = hashlib.sha3_256(a).digest()
    return a


def decrypt(blob: bytes, password: bytes) -> bytes:
    key = derive_keys(password, blob)
    nonce_24 = blob[89:113]
    ct_and_tag = blob[113:]
    ciphertext = ct_and_tag[:-16]  # strip 16-byte tag (not verified)

    subkey = hchacha20(key, nonce_24[:16])
    plaintext = chacha20_xor(subkey, nonce_24[16:24], ciphertext, counter_start=1)
    return plaintext


def main():
    import argparse
    import getpass
    import os

    ap = argparse.ArgumentParser(
        description="Decrypt a 1inch Wallet backup. "
                    "By DEFAULT output is re-encrypted into a portable vault using "
                    "the same passphrase — plaintext seeds never touch the disk.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("backup", help="path to backup.1inch")
    ap.add_argument("password", nargs="?", default=None,
                    help="(discouraged) passphrase on command line; otherwise $ONEINCH_PASSWORD or prompt")
    ap.add_argument(
        "--unsafe-plaintext", action="store_true",
        help="DANGEROUS: write the decrypted JSON (with seeds) in plaintext. "
             "Anyone who copies the file can drain the wallets. Use only on encrypted disks.",
    )
    ap.add_argument("-o", "--output", default=None, help="output path (default: <backup>.vault or .plaintext.json)")
    args = ap.parse_args()

    path = Path(args.backup)
    if args.password:
        print(
            "[!] warning: passphrase on command line is visible to other local "
            "users (ps, /proc) and shell history. Prefer $ONEINCH_PASSWORD or prompt.",
            file=sys.stderr,
        )
        password = args.password.encode("utf-8")
    elif os.environ.get("ONEINCH_PASSWORD"):
        password = os.environ["ONEINCH_PASSWORD"].encode("utf-8")
    else:
        password = getpass.getpass("Passphrase: ").encode("utf-8")

    blob = path.read_bytes()
    print(f"[+] blob = {len(blob)} bytes")

    try:
        pt = decrypt(blob, password)
    except Exception as e:
        print(f"[!] decrypt error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        data = json.loads(pt.rstrip(b"\x00"))
    except json.JSONDecodeError:
        print(f"[!] decrypt produced non-JSON (likely wrong password)")
        sys.exit(3)

    n_wallets = sum(len(a.get("wallets", [])) for a in data.get("accounts", []))
    print(f"[+] decrypted successfully — {n_wallets} wallet(s) across "
          f"{len(data.get('accounts', []))} account(s)")

    plaintext_json = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")

    def write_secure(p: Path, payload: bytes):
        if p.exists():
            ans = input(f"[?] {p} exists. Overwrite? [y/N] ")
            if ans.strip().lower() != "y":
                print("[!] aborted.")
                sys.exit(4)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)

    if args.unsafe_plaintext:
        out = Path(args.output) if args.output else path.with_suffix(".plaintext.json")
        print("\033[31m[!] WARNING: writing PLAINTEXT wallets to disk.\033[0m")
        print("    Any process, backup tool, or user with read access CAN DRAIN these wallets.")
        print("    Shred the file as soon as you are done: shred -uz " + str(out))
        write_secure(out, plaintext_json)
        print(f"[+] wrote {out} (chmod 600, PLAINTEXT)")
    else:
        # Default: re-encrypt with SAME passphrase in portable vault format
        try:
            from oneinch_vault import encrypt as vault_encrypt
        except ImportError:
            # allow running from any dir
            import importlib.util as _u
            _spec = _u.spec_from_file_location(
                "oneinch_vault", Path(__file__).parent / "oneinch_vault.py")
            _mod = _u.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            vault_encrypt = _mod.encrypt
        vault = vault_encrypt(plaintext_json, password)
        out = Path(args.output) if args.output else path.with_suffix(".vault")
        write_secure(out, vault)
        print(f"[+] wrote {out} ({len(vault)} bytes, chmod 600)")
        print(f"[+] re-encrypted with the SAME passphrase using portable vault format")
        print(f"    Decrypt later:  python3 oneinch_vault.py decrypt {out} -o plaintext.json")


if __name__ == "__main__":
    main()
