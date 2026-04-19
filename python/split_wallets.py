#!/usr/bin/env python3
"""
Split un JSON BackupData3 capturé (Frida hook) en N fichiers, 1 par wallet.

Usage:
    python3 split_wallets.py <input_json_or_log_or_-> [output_dir]

Accepts:
    - Path to a .json file with the decrypted BackupData3
    - Path to the frida log file (auto-extracts between --- JSON START/END ---)
    - "-" to read from stdin

Output: <output_dir>/wallet-<idx>-<eth_prefix>_<name_slug>.json (chmod 600)
"""
import datetime
import json
import os
import re
import stat
import sys
from pathlib import Path

from mnemonic import Mnemonic

MNEMO = Mnemonic("english")
SLUG_RE = re.compile(r"[^A-Za-z0-9_-]+")


def load_input(path: str) -> dict:
    if path == "-":
        blob = sys.stdin.read()
    else:
        blob = Path(path).read_text(errors="replace")

    # Direct JSON?
    blob_stripped = blob.strip()
    if blob_stripped.startswith("{"):
        return json.loads(blob_stripped)

    # Frida log format: lines between --- (JSON|PLAINTEXT) START --- and END ---
    # May appear multiple times — pick the LARGEST (real data vs trivial first-run checks)
    matches = re.findall(
        r"---\s*(?:JSON|PLAINTEXT)\s*START\s*---(.*?)---\s*(?:JSON|PLAINTEXT)\s*END\s*---",
        blob, flags=re.DOTALL | re.IGNORECASE,
    )
    if matches:
        # pick longest
        chunk = max(matches, key=len)
        lines = [ln.lstrip() for ln in chunk.splitlines() if ln.strip()]
        joined = "".join(lines)
        return json.loads(joined)

    raise ValueError("Could not find JSON — provide raw json file or frida log")


def entropy_to_mnemonic(entropy_hex: str) -> str:
    if entropy_hex.startswith("0x"):
        entropy_hex = entropy_hex[2:]
    return MNEMO.to_mnemonic(bytes.fromhex(entropy_hex))


def slug(s: str, maxlen: int = 20) -> str:
    s = SLUG_RE.sub("_", (s or "").strip())[:maxlen]
    return s or "wallet"


def split(data: dict, out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)

    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    idx = 0
    accounts = data.get("accounts") or []
    if not accounts:
        print("[!] No accounts[] in input", file=sys.stderr)
        return 0

    for acct in accounts:
        roots = {r["id"]: r for r in (acct.get("roots") or [])}
        for w in acct.get("wallets") or []:
            idx += 1
            root_id = w.get("rootId")
            root = roots.get(root_id, {})

            entry = {
                "index": idx,
                "id": root_id,
                "name": w.get("name"),
                "addresses": {
                    "eth": w.get("addressEth"),
                    "sol": w.get("addressSol"),
                },
                "derivation_paths": {
                    "eth": w.get("derivationPathEth"),
                    "sol": w.get("derivationPathSol"),
                },
                "entropy": None,
                "mnemonic": None,
                "mnemonic_words": None,
                "private_key": None,
                "hw_device_id": w.get("hwDeviceId"),
                "captured_at": now,
            }

            ent = root.get("entropy")
            if ent:
                clean = ent[2:] if ent.startswith("0x") else ent
                entry["entropy"] = clean
                try:
                    mnem = entropy_to_mnemonic(ent)
                    entry["mnemonic"] = mnem
                    entry["mnemonic_words"] = len(mnem.split())
                except Exception as e:
                    entry["mnemonic_error"] = str(e)

            priv = root.get("private")
            if priv:
                entry["private_key"] = priv[2:] if priv.startswith("0x") else priv

            # Filename
            eth = (w.get("addressEth") or "")[:10] or f"noaddr{idx:04d}"
            name_s = slug(w.get("name") or "")
            fname = f"wallet-{idx:04d}-{eth}_{name_s}.json"
            target = out_dir / fname

            payload = json.dumps(entry, indent=2, ensure_ascii=False)
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, payload.encode("utf-8"))
            finally:
                os.close(fd)
            os.chmod(target, 0o600)

    return idx


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_json_or_log> [output_dir]", file=sys.stderr)
        sys.exit(1)

    src = sys.argv[1]
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "wallets-out").resolve()

    data = load_input(src)
    n = split(data, out)
    print(f"[+] Wrote {n} wallet file(s) to {out}")
    print(f"    Dir perms: 700, File perms: 600")


if __name__ == "__main__":
    main()
