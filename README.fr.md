# Décrypteur de backup 1inch Wallet

[🇬🇧 English](README.md) · 🇫🇷 Français

**▶ Ouvrir l'outil : https://meumeu-dev.github.io/oneinch-backup-decryptor/**

Outil open-source de récupération **chiffré de bout en bout**, **100 % côté client**, pour les fichiers de sauvegarde `.1inch` du 1inch Wallet Android (format v3). Une seule page HTML. Aucun serveur. Aucun réseau après le chargement de la page.

Fonctionne dans tout navigateur moderne. Fonctionne aussi hors-ligne depuis une clé USB (ouvrir `index.html` directement via `file://…`).

---

## ⚠️ Avertissement

**Cet outil sert à récupérer TES PROPRES backups.** À utiliser uniquement avec des fichiers dont tu es légalement propriétaire et dont tu connais la passphrase.

- Non affilié à 1inch Network / 1inch Limited / Degensoft Ltd. « 1inch Wallet » et « 1inch » sont des marques déposées de leurs ayants droit respectifs, mentionnées ici dans le seul but d'identifier le format de fichier que l'outil traite (usage nominatif / fair use).
- Aucun code source propriétaire de 1inch Wallet n'est inclus. Le format de backup a été obtenu par reverse engineering de l'APK Android librement distribué, à des fins d'interopérabilité — ce qui est expressément autorisé par la Directive européenne 2009/24/CE art. 6 et le DMCA US §1201(f).
- Fourni **EN L'ÉTAT**, sans garantie. Tu es seul responsable de l'usage que tu fais de ce logiciel et des clés qu'il récupère.
- Sous licence **GNU AGPL v3**. Si tu héberges cet outil comme service en ligne, tu dois publier aussi la source de tes éventuelles modifications aux utilisateurs de ce service.

Mention légale complète dans [`LEGAL.md`](LEGAL.md).

---

## Utilisation

### Option 1 — en local (aucun serveur, aucun réseau)

```bash
git clone https://github.com/meumeu-dev/oneinch-backup-decryptor
cd oneinch-backup-decryptor
xdg-open index.html    # Linux
open index.html         # macOS
start index.html        # Windows
```

Le fichier s'ouvre dans ton navigateur par défaut. Dépose ton fichier `.1inch`, saisis la passphrase, clique sur **Déchiffrer**. Fonctionne totalement hors-ligne.

### Option 2 — n'importe quel hébergeur statique

La racine du dépôt est un site statique ordinaire. Pointe GitHub Pages / Netlify / Vercel / S3 / nginx / caddy / `python3 -m http.server` dessus, peu importe. La balise `<meta http-equiv="Content-Security-Policy">` dans `index.html` impose `connect-src 'none'`, donc la garantie E2EE tient quel que soit l'hébergeur.

Pour GitHub Pages en particulier : dans les paramètres du repo, configure la source Pages sur la branche `main`, `/ (root)`. Le fichier `.nojekyll` est déjà présent pour désactiver Jekyll.

---

## Sortie par défaut = sûre

Le seul téléchargement produit par défaut est un **vault rechiffré** (`wallets.vault`), chiffré avec la même passphrase que tu viens de saisir, via XChaCha20-Poly1305 + Argon2id standard. Tes seeds en clair ne touchent jamais le disque.

Si tu as besoin du JSON en clair (ou d'un ZIP avec un JSON par wallet), coche la case **⚠ Préparer aussi les exports en clair** avant de cliquer sur Déchiffrer. Un bloc rouge apparaîtra avec les liens de téléchargement. À utiliser uniquement sur une machine de confiance et éphémère, puis `shred -uz` les fichiers.

## Rouvrir un `.vault` plus tard

Le même outil gère les deux sens. Bascule sur l'onglet **« Ouvrir un .vault »**, dépose ton `wallets.vault`, entre la passphrase, clique sur **Ouvrir le vault** → tu récupères la liste des wallets, avec possibilité de re-exporter en clair.

Le format `.vault` est un blob AEAD XChaCha20-Poly1305 standard libsodium, précédé d'un en-tête de 80 octets (magic `1ivault\0`, version, paramètres Argon2id, sel, nonce). N'importe quel outil libsodium-compatible peut le déchiffrer à condition de respecter l'en-tête — voir « Format du vault rechiffré » plus bas. Bibliothèques compatibles : `libsodium.js`, `pynacl` en Python, `golang.org/x/crypto/chacha20poly1305` en Go, `libsodium` en C.

---

## E2EE, vérifiable

La page affiche un badge 🔒 E2EE dans l'en-tête, avec une sonde type check :

- Au chargement, elle tente un `fetch()` bénin vers un hôte externe.
- Si le navigateur autorise le fetch → le déploiement n'est **pas** isolé, et le bouton Déchiffrer reste désactivé avec une bannière rouge.
- Si le navigateur refuse (CSP `connect-src 'none'` ou sandbox `file://`) → le badge passe au vert et le déchiffrement est débloqué.

Autrement dit : même si quelqu'un trafique la page en transit, le déchiffrement ne peut littéralement pas s'exécuter sur un déploiement qui permettrait d'exfiltrer ta passphrase. Vérifiable toi-même en désactivant la meta CSP et en rechargeant.

Défenses supplémentaires :

- **Subresource Integrity** sur chaque script externe (`argon2-browser`, `js-sha3`, `JSZip`, la wordlist BIP-39).
- **Vérification SHA-256 au runtime** de la wordlist BIP-39 avant de générer la moindre mnemonic — une liste altérée produirait silencieusement des phrases qui décodent la bonne entropy en mauvais mots, c'est exactement le genre d'attaque supply-chain à empêcher.
- **Frame-buster** contre le clickjacking / UI-redress.
- **Balises d'opt-out** (robots.txt, ai.txt, `<meta name="robots">`, `<meta name="GPTBot">`, etc.) pour décourager l'indexation et le scraping par les IA.

---

## Détails cryptographiques (pour auditeurs)

Format v3 1inch reverse engineered :

```
offset  taille  champ
------  ------  ------
  0     11      magic = "1inchbackup"
 11      2      version (int16)  = 3
 13     32      sel Argon2id (aléatoire par backup)
 45      4      t_cost (u32)           [2]
 49      4      m_cost (u32, KiB)      [65536 = 64 MiB]
 53      4      parallélisme (u32)     [1]
 57     32      32 octets aléatoires réservés (par backup, inutilisés au déchiffrement)
 89     24      nonce XChaCha20 (aléatoire par backup)
113      N      ciphertext ChaCha20  (N = longueur plaintext)
113+N   16      tag Poly1305 (construction non standard, non vérifié)
```

Pipeline de dérivation de clé :

```
KEK       = Argon2id(passphrase, sel, t, m, p, hashLen = 32)
A         = SHA3-256 itéré 30 001 fois sur KEK
subkey    = HChaCha20(A, nonce[0:16])
plaintext = ChaCha20-classic(subkey, nonce[16:24], ciphertext, compteur = 1)
```

Après déchiffrement, `plaintext` est un JSON UTF-8 avec `accounts[].wallets[]` (adresses, chemins de dérivation) et `accounts[].roots[]` (`entropy` pour les HD wallets, `private` pour les wallets importés depuis une clé privée). L'outil convertit l'entropy BIP-39 en mnemonic 12 / 24 mots via la wordlist anglaise canonique.

## Format du vault rechiffré

```
offset  taille  champ
------  ------  ------
  0      8      magic = "1ivault\0"
  8      1      version = 1
  9      3      réservé
 12      4      Argon2id t_cost (u32)     [défaut 4]
 16      4      Argon2id m_cost KiB (u32) [défaut 262144 = 256 MiB]
 20      4      Argon2id parallélisme (u32) [défaut 1]
 24     32      sel Argon2id
 56     24      nonce XChaCha20
 80      N      ciphertext XChaCha20-Poly1305 + tag 16 octets
```

C'est le schéma AEAD XChaCha20-Poly1305 standard de libsodium avec des paramètres Argon2id solides par défaut. Déchiffrable par n'importe quel outil compatible libsodium qui respecte cet en-tête.

---

## Organisation des sources

```
.
├── index.html                 l'appli (~500 lignes de JS, auditable)
├── .nojekyll                  désactive Jekyll sur GitHub Pages
├── robots.txt                 opt-out crawlers / IA
├── ai.txt                     signal IETF ai.txt
├── README.md · README.fr.md · LEGAL.md · LICENSE
└── vendor/
    ├── argon2-bundled.min.js  argon2-browser 1.18.0 (WASM, SRI épinglé)
    ├── sha3.min.js            js-sha3 0.9.3 (SRI épinglé)
    ├── jszip.min.js           JSZip 3.10.1 (SRI épinglé)
    ├── bip39-english.js       wordlist BIP-39 anglaise inlinée (SRI épinglée)
    └── bip39-english.txt      forme texte, conservée pour l'audit
```

JavaScript total à auditer, vendor inclus : ~170 KB minifié.

---

## Licence

**GNU Affero General Public License v3.0.** Voir [`LICENSE`](LICENSE).

Si tu déploies ce logiciel comme service réseau, tu dois proposer la source de tes modifications aux utilisateurs de ce service. C'est volontaire : ça empêche quelqu'un de prendre cet outil de récupération, de le wrapper dans un backend hostile qui capture les passphrases, et de le revendre en SaaS.

## Légal

Voir [`LEGAL.md`](LEGAL.md) pour la mention légale complète : disclaimer, usage loyal (EU 2009/24/CE art. 6 et DMCA §1201(f) US), contrôles export, procédure de divulgation de vulnérabilités.
