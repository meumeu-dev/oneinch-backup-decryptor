# Legal Notice

## Purpose

This software is a **wallet-recovery and migration utility** for backups that the
user personally created in 1inch Wallet. It is distributed in the honest belief
that users have a right to the data and keys held inside their own encrypted
backups, for purposes including (but not limited to):

- recovering wallets after losing or uninstalling the mobile app,
- migrating wallets to another self-custody wallet of the user's choice,
- archiving wallets under the user's own cryptographic control,
- auditing the security of the backup format,
- academic / journalistic / security research.

## Disclaimer of warranty

This software is provided **"AS IS"** without warranty of any kind, express or
implied. The authors make no guarantee that it will work correctly for any
particular backup file, nor that it will not damage, corrupt, or expose the
data you feed into it. Use of this software is entirely at your own risk.

See the LICENSE file (GNU AGPL v3) for the full legal wording of the warranty
disclaimer and limitation of liability.

## Acceptable use — user responsibility

By using this software you assert that:

1. **You own the backup file you are processing**, or you have explicit, lawful
   authorisation from its owner to decrypt it.
2. **You possess the passphrase** that was chosen when the backup was created.
   (The tool cannot recover an unknown passphrase; it only decrypts.)
3. **You are not using the software** to access wallets that do not belong to
   you, to bypass a lock that is not yours, to steal funds, or to commit any
   act that would be unlawful under the jurisdiction in which you operate.

Misuse — including but not limited to decrypting a backup obtained without
permission, or exploiting this tool to access third-party funds — is not a
bug in the software, it is a choice the operator makes, and they bear sole
responsibility for it.

## No affiliation

This project is **not affiliated with, endorsed by, or sponsored by 1inch
Network**, 1inch Limited, Degensoft Ltd., or any related entity. "1inch
Wallet" and "1inch" are trademarks of their respective owners; they are used
here solely to identify the backup-file format this tool operates on, under
the principles of nominative fair use.

No proprietary source code from 1inch Wallet is included in this project.
The backup format was reverse-engineered from the freely-distributed
Android binary (`io.oneinch.android`) for the purposes of interoperability
— a use that is expressly permitted under:

- the EU Software Directive 2009/24/EC, Article 6 (interoperability);
- US DMCA § 1201(f) (reverse engineering for interoperability);
- comparable provisions in most other jurisdictions.

## Export control

This software contains strong cryptographic primitives (Argon2id,
XChaCha20-Poly1305, ChaCha20, SHA-3). It is published as free and open-source
software and its algorithms are publicly documented; as such it is generally
exempt from US EAR controls under License Exception TSU (15 CFR § 740.13(e))
and equivalent provisions in the EU Dual-Use Regulation. You remain responsible
for complying with any additional export / import controls that apply to your
jurisdiction or use case.

## Reporting security issues

If you find a security vulnerability in this tool — especially one that could
leak a passphrase or wallet secret to a third party — please report it
privately via the GitHub "Report a security vulnerability" feature on the
repository, not as a public issue. The author will respond as quickly as
possible and credit you in the fix (if you wish).

## No financial advice

This tool decrypts wallets. It does not advise you on what to do with the
recovered keys. Handling cryptocurrency wallets involves substantial risk,
including total loss of funds. You are responsible for your own operational
security, transaction decisions, tax reporting, and everything else.
