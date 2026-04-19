# 1inch Wallet Backup Decryptor

Standalone, offline, open-source decryptor for 1inch Wallet Android `.1inch` backup files (format v3).

Three flavours ship side-by-side, all producing **bit-identical output**:

| Stack | Entry point | Deps | Use case |
|-------|-------------|------|----------|
| Python 3 | `python/oneinch_decrypt.py` | `argon2-cffi` | CLI, scripting, automation |
| Go (static binary) | `go/main.go` | `golang.org/x/crypto` | single binary, air-gap |
| HTML + JS | `web/index.html` | argon2-browser, js-sha3, JSZip | runs in a browser, 100% client-side |

Bonus: `python/oneinch_vault.py` re-encrypts the extracted data in a **portable, standards-compliant** format (XChaCha20-Poly1305 + Argon2id), so you can archive your wallets without the 1inch format.

---

## ⚠️ Disclaimer

**This tool is for recovering YOUR OWN backups.** Use only with files you legally own and possess the passphrase for.

- Not affiliated with 1inch Network / 1inch Limited / Degensoft Ltd. "1inch Wallet" and "1inch" are trademarks of their respective owners, used here solely to identify the backup format this tool processes (nominative fair use).
- No proprietary source code from 1inch Wallet is included. The backup format was reverse-engineered from the freely-distributed Android APK for interoperability, expressly permitted under EU Directive 2009/24/EC Art. 6 and US DMCA §1201(f).
- Provided **AS IS**, with no warranty. You are solely responsible for any use you make of this software or the keys it recovers.
- Licensed under **GNU AGPL v3** — if you deploy this software as a network service, you must also release the source of your modifications to the users of that service.

See [`LEGAL.md`](LEGAL.md) for the full legal notice and [`LICENSE`](LICENSE) for the AGPL-3.0 text.

---

## Safe defaults

**Every CLI tool re-encrypts the output by default**, using the same passphrase you typed for decryption. Plaintext seeds never hit the disk. The plaintext JSON is gated behind an explicit `--unsafe-plaintext` flag plus a red runtime warning. Same for the web UI (plaintext downloads are hidden behind a `<details>` block with a warning).

The passphrase is never read from `argv` by default: use `$ONEINCH_PASSWORD` or the interactive TTY prompt. Passing the password on the command line triggers a visible warning because `ps` and shell history will leak it.

## Quick start

### Python

```bash
cd python
pip install argon2-cffi pynacl mnemonic
ONEINCH_PASSWORD='your passphrase' python3 oneinch_decrypt.py /path/to/backup.1inch
# → backup.vault  (re-encrypted with the SAME passphrase, portable XChaCha20-Poly1305)

# Decrypt the vault later:
ONEINCH_VAULT_PASSWORD='your passphrase' python3 oneinch_vault.py decrypt backup.vault -o plaintext.json

# Explicit plaintext (not recommended):
ONEINCH_PASSWORD='your passphrase' python3 oneinch_decrypt.py --unsafe-plaintext /path/to/backup.1inch

# Split the plaintext JSON into per-wallet files (one file per wallet, chmod 600):
python3 split_wallets.py plaintext.json out/
```

### Go

```bash
cd go
go build -o oneinch-decrypt .
ONEINCH_PASSWORD='your passphrase' ./oneinch-decrypt /path/to/backup.1inch
# → backup.1inch.vault  (same format as Python, interoperable)

# Plaintext (risky):
ONEINCH_PASSWORD='…' ./oneinch-decrypt --unsafe-plaintext /path/to/backup.1inch
```

### HTML (browser, offline)

```bash
# Any static file server works — or open index.html directly from disk (file://).
cd web && python3 -m http.server 8765
# visit http://localhost:8765/ — drop your backup, type passphrase, Decrypt
# Primary download: wallets.vault (re-encrypted, same format as the CLI tools).
# Plaintext JSON + per-wallet zip are hidden behind a collapsed warning block.
```

All dependencies are vendored locally under `web/vendor/`. **No network calls** after initial page load. Subresource Integrity (SRI) hashes guard the vendored scripts, and a `<meta http-equiv="Content-Security-Policy">` tag enforces `connect-src 'none'` so a tampered page still cannot exfiltrate your passphrase.

### Static hosting

There is no backend. Any static host works:

- **GitHub Pages** — push the `web/` folder as the Pages source. The included `.nojekyll` disables Jekyll. The meta CSP inside the HTML enforces E2EE on plain-static hosting.
- **Local file** — save `web/` to disk and open `index.html` with your browser (`file://…`). Works fully offline, including air-gapped.
- **Netlify, Vercel, S3, nginx** — same: just serve the `web/` folder.

Cross-check: the page shows a live network-isolation badge at the top. If your host doesn't enforce the CSP, the badge will warn you.

---

## Reverse-engineered backup format (v3)

Binary layout, little-endian throughout:

```
offset  size  field
------  ----  -----
  0     11    magic = b"1inchbackup"
 11      2    version (int16) = 3
 13     32    Argon2id salt (random per backup)
 45      4    t_cost (u32)           — typically 2
 49      4    m_cost (u32, in KiB)   — typically 65536 (= 64 MiB)
 53      4    parallelism (u32)      — typically 1
 57     32    unused 32 bytes random per backup (appears unreferenced by decrypt)
 89     24    XChaCha20 nonce (random per backup)
113      N    ChaCha20 ciphertext (N = plaintext length)
113+N   16    Poly1305 tag (non-standard construction — not verified by this tool)
```

### Key derivation pipeline

```
KEK     = Argon2id(password, salt, t, m, p, hashLen = 32)
A       = SHA3-256 iterated 30_001 times over KEK
subkey  = HChaCha20(A, nonce[0:16])
plaintext = ChaCha20-classic(subkey, nonce[16:24], ciphertext, counter = 1)
```

The SHA3 stretching loop (30 001 rounds on a 32-byte buffer) is the obfuscation layer: it is easy to describe but forces anyone to derive the key by reimplementation. All of this runs in well under a second on any modern CPU.

The Poly1305 authentication tag uses a custom construction we did not reverse. Because we can still decrypt perfectly, the tag is skipped — the decrypted JSON parses cleanly, which is our implicit integrity check.

---

## Threat model

- **Input**: your own encrypted `.1inch` file.
- **Secret**: passphrase you typed into 1inch Wallet when you created the backup.
- **Adversary**: the tool itself, CDN/hosting providers, network observers.

Mitigations:
- Python / Go / JS implementations are small and auditable (< 300 lines each).
- HTML version runs entirely in-browser; there is no backend.
- CF Worker deployment serves static assets only. Strict `Content-Security-Policy` forbids outbound connections.
- Output files are created with `chmod 600` and the JSON contains the seeds in clear — **treat them like the originals**.

---

## Extracted wallet fields

Each wallet in the output JSON (or each file in the split) contains:

```json
{
  "name": "Wallet name (user-chosen)",
  "addressEth": "0x<40-hex-chars>",
  "addressSol": "<base58 pubkey>",
  "derivationPathEth": "m/44'/60'/0'/0/0",
  "derivationPathSol": "m/44'/501'/0'/0'",
  "entropy": "<16 or 32 hex bytes>",
  "mnemonic": "<12 or 24 BIP-39 words>",
  "private_key": null,
  "hwDeviceId": null
}
```

`entropy` is the BIP-39 input entropy. `mnemonic` is the standard-English 12/24-word phrase derived from it. `private_key` is only populated for wallets imported via a raw private key rather than a seed phrase.

## Re-encrypt in a portable vault

```bash
# The passphrase is read from $ONEINCH_VAULT_PASSWORD or prompted — not argv.
ONEINCH_VAULT_PASSWORD='…' python3 python/oneinch_vault.py encrypt wallets.json -o wallets.vault
ONEINCH_VAULT_PASSWORD='…' python3 python/oneinch_vault.py decrypt wallets.vault -o wallets.json
```

Uses standard XChaCha20-Poly1305 AEAD + Argon2id (`t=4`, `m=256 MiB`, `p=1` by default — tweakable via `-t/-m/-p`). Decryptable with any libsodium-compatible tool that follows the header layout documented in `python/oneinch_vault.py`.

---

## License

**GNU Affero General Public License v3.0.** See [`LICENSE`](LICENSE).

If you deploy this software as a network-accessible service, you must offer the source of your modifications to the users of that service. This is on purpose: it prevents someone from taking this recovery tool, wrapping it in a hostile backend that captures passphrases, and selling it as SaaS.

## Legal

See [`LEGAL.md`](LEGAL.md) for the full disclaimer, fair-use assertion (EU 2009/24/EC Art. 6 and US DMCA §1201(f)), export-control notice, and vulnerability-disclosure policy.
