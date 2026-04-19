# 1inch Wallet Backup Decryptor

Open-source, **end-to-end encrypted**, **100 % client-side** recovery tool for 1inch Wallet Android `.1inch` backup files (format v3). A single HTML page. No server. No network after page load.

Runs in any modern browser. Also runs offline from a USB stick (open `index.html` directly with `file://…`).

---

## ⚠️ Disclaimer

**This tool is for recovering YOUR OWN backups.** Use only with files you legally own and for which you possess the passphrase.

- Not affiliated with 1inch Network / 1inch Limited / Degensoft Ltd. "1inch Wallet" and "1inch" are trademarks of their respective owners, used here solely to identify the file format this tool processes (nominative fair use).
- No proprietary source code from 1inch Wallet is included. The backup format was reverse-engineered from the freely-distributed Android APK for interoperability, expressly permitted under EU Directive 2009/24/EC Art. 6 and US DMCA §1201(f).
- Provided **AS IS**, no warranty. You are solely responsible for any use you make of this software or the keys it recovers.
- Licensed under **GNU AGPL v3**. If you host this software as a network service, you must also release the source of your modifications to users of that service.

Full notice in [`LEGAL.md`](LEGAL.md).

---

## How to use

### Option 1 — open it locally (no server, no network)

```bash
git clone https://github.com/<you>/oneinch-backup-decryptor
cd oneinch-backup-decryptor
xdg-open index.html    # Linux
open index.html         # macOS
start index.html        # Windows
```

The file opens in your default browser. Drop your `.1inch` file, type the passphrase, click **Decrypt**. Works completely offline.

### Option 2 — any static host

The repository root is a plain static site. Point GitHub Pages / Netlify / Vercel / S3 / nginx / caddy / `python3 -m http.server` at it, whatever. The `<meta http-equiv="Content-Security-Policy">` tag inside `index.html` enforces `connect-src 'none'` so the E2EE guarantee holds on any host.

For GitHub Pages specifically: in the repo settings, set the Pages source to `main` branch, `/ (root)`. The `.nojekyll` file disables Jekyll.

---

## Safe-by-default output

The primary download after decryption is a **re-encrypted vault** (`wallets.vault`), encrypted with the same passphrase you just typed, using standard XChaCha20-Poly1305 + Argon2id. Your plaintext seeds never touch the disk unless you explicitly ask for them.

If you need the raw plaintext JSON (or a ZIP with one JSON per wallet), it is hidden behind a collapsed **⚠ Exports EN CLAIR** block with a red warning. Use it only on a trusted, ephemeral machine, and `shred -uz` the files afterwards.

---

## E2EE, verifiable

The page shows a live 🔒 E2EE badge at the top, next to a checkbox-style probe:

- On page load it attempts a harmless `fetch()` to an external host.
- If the browser allows the fetch → the deployment is **not** isolated, and the Decrypt button stays disabled with a red banner.
- If the browser refuses (CSP `connect-src 'none'` or `file://` sandbox) → the badge turns green and decryption unlocks.

So: even if someone tampered with the page in transit, the decryption literally cannot run on a deployment that could exfiltrate your passphrase. You can verify this for yourself by disabling the meta CSP and reloading.

Additional defenses:

- **Subresource Integrity** on every vendor script (`argon2-browser`, `js-sha3`, `JSZip`, the BIP-39 wordlist).
- **Runtime SHA-256 check** on the BIP-39 wordlist before any mnemonic is computed — a tampered wordlist would silently generate wrong phrases that decode the right entropy to the wrong words, which is exactly the kind of supply-chain attack we must prevent.
- **Frame-buster** against clickjacking / UI-redress.
- **Opt-out tags** (robots.txt, ai.txt, `<meta name="robots">`, `<meta name="GPTBot">`, etc.) to discourage indexing and AI scraping.

---

## Cryptographic internals (for auditors)

The reverse-engineered 1inch v3 backup format:

```
offset  size  field
------  ----  -----
  0     11    magic = "1inchbackup"
 11      2    version (int16)  = 3
 13     32    Argon2id salt (per-backup random)
 45      4    t_cost (u32)           [2]
 49      4    m_cost (u32, KiB)      [65536 = 64 MiB]
 53      4    parallelism (u32)      [1]
 57     32    reserved 32 random bytes (per-backup, unused by decrypt)
 89     24    XChaCha20 nonce (per-backup random)
113      N    ChaCha20 ciphertext  (N = plaintext length)
113+N   16    Poly1305 tag (non-standard construction, not verified)
```

Key derivation pipeline:

```
KEK     = Argon2id(password, salt, t, m, p, hashLen = 32)
A       = SHA3-256 iterated 30 001 times over KEK
subkey  = HChaCha20(A, nonce[0:16])
plain   = ChaCha20-classic(subkey, nonce[16:24], ciphertext, counter = 1)
```

After decryption, `plain` is a UTF-8 JSON blob with `accounts[].wallets[]` (addresses, derivation paths) and `accounts[].roots[]` (`entropy` for HD wallets; `private` for private-key-imported ones). The tool maps BIP-39 entropy to its 12/24-word mnemonic via the canonical English wordlist.

## Re-encrypted vault format

```
offset  size  field
------  ----  -----
  0      8    magic = "1ivault\0"
  8      1    version = 1
  9      3    reserved
 12      4    Argon2id t_cost (u32)    [default 4]
 16      4    Argon2id m_cost KiB (u32) [default 262144 = 256 MiB]
 20      4    Argon2id parallelism (u32) [default 1]
 24     32    Argon2id salt
 56     24    XChaCha20 nonce
 80      N    XChaCha20-Poly1305 ciphertext + 16-byte tag
```

This is the libsodium-standard XChaCha20-Poly1305 AEAD with a strong default Argon2id cost. Decryptable with any libsodium-compatible tool that respects the header.

---

## Source layout

```
.
├── index.html                 main app (≈ 500 lines JS, audit-friendly)
├── .nojekyll                  disables Jekyll on GitHub Pages
├── robots.txt                 crawler / AI opt-out
├── ai.txt                     IETF ai.txt opt-out signal
├── README.md · LEGAL.md · LICENSE
└── vendor/
    ├── argon2-bundled.min.js  argon2-browser 1.18.0 (WASM, SRI pinned)
    ├── sha3.min.js            js-sha3 0.9.3 (SRI pinned)
    ├── jszip.min.js           JSZip 3.10.1 (SRI pinned)
    ├── bip39-english.js       inlined BIP-39 English wordlist (SRI pinned)
    └── bip39-english.txt      text form, kept for auditing
```

Total JavaScript you have to trust, including vendor: about 170 KB minified.
