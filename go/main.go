// 1inch Wallet backup v3 decryptor — pure Go (no CGO).
//
// Default output is a RE-ENCRYPTED portable vault (.vault) using the SAME
// passphrase — plaintext seeds never touch the disk. Use --unsafe-plaintext
// to write the decrypted JSON (with WARNING).
//
// Usage:
//     oneinch-decrypt [--unsafe-plaintext] <backup.1inch>
//         → passphrase from $ONEINCH_PASSWORD or TTY prompt
package main

import (
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	magic     = "1inchbackup"
	sha3Iter  = 30001
	keyLen    = 32
	tagLen    = 16
	nonceLen  = 24
	saltLen   = 32
	headerLen = 113 // 11 magic + 2 version + 32 salt + 12 params + 32 unknown + 24 nonce
)

// rotl32 left-rotate 32-bit.
func rotl32(x, n uint32) uint32 { return (x << n) | (x >> (32 - n)) }

func qr(s []uint32, a, b, c, d int) {
	s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16)
	s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12)
	s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8)
	s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7)
}

// hchacha20 derives a 32-byte subkey from a 32-byte key and 16-byte nonce.
func hchacha20(key []byte, nonce16 []byte) []byte {
	if len(key) != 32 || len(nonce16) != 16 {
		panic("hchacha20 sizes")
	}
	state := []uint32{
		0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
		binary.LittleEndian.Uint32(nonce16[0:4]),
		binary.LittleEndian.Uint32(nonce16[4:8]),
		binary.LittleEndian.Uint32(nonce16[8:12]),
		binary.LittleEndian.Uint32(nonce16[12:16]),
	}
	for i := 0; i < 10; i++ {
		qr(state, 0, 4, 8, 12); qr(state, 1, 5, 9, 13)
		qr(state, 2, 6, 10, 14); qr(state, 3, 7, 11, 15)
		qr(state, 0, 5, 10, 15); qr(state, 1, 6, 11, 12)
		qr(state, 2, 7, 8, 13); qr(state, 3, 4, 9, 14)
	}
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[4*i:], state[i])
	}
	for i := 12; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[4*(i-12)+16:], state[i])
	}
	return out
}

// deriveKey runs the 1inch KDF pipeline.
//   KEK = Argon2id(pwd, salt, t, m, p, 32)
//   A   = SHA3-256 iterated 30,001 times on KEK
func deriveKey(password, salt []byte, t, m, p uint32) []byte {
	// argon2.IDKey: memory param is in KiB (matches Python argon2-cffi memory_cost)
	kek := argon2.IDKey(password, salt, t, m, uint8(p), keyLen)
	a := kek
	for i := 0; i < sha3Iter; i++ {
		h := sha3.New256()
		h.Write(a)
		a = h.Sum(nil)
	}
	return a
}

// chacha20ClassicXOR decrypts with ChaCha20 classic (8-byte nonce), counter starts at 1.
// Poly1305 tag is NOT verified (1inch uses non-standard AEAD).
func chacha20ClassicXOR(key, nonce8, data []byte, counterStart uint64) []byte {
	// golang.org/x/crypto/chacha20 uses IETF nonce (12B). For classic (8B nonce),
	// construct equivalent IETF nonce by prepending 4 zero bytes + using same state layout.
	// Actually classic ChaCha20 differs in counter: 8B counter + 8B nonce vs IETF 4B counter + 12B nonce.
	// We need to implement manually for classic.
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 64 {
		blockEnd := i + 64
		if blockEnd > len(data) {
			blockEnd = len(data)
		}
		ks := chachaClassicBlock(key, nonce8, counterStart+uint64(i/64))
		for j := i; j < blockEnd; j++ {
			out[j] = data[j] ^ ks[j-i]
		}
	}
	return out
}

func chachaClassicBlock(key, nonce8 []byte, counter uint64) []byte {
	state := []uint32{
		0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
		uint32(counter & 0xFFFFFFFF),
		uint32(counter >> 32),
		binary.LittleEndian.Uint32(nonce8[0:4]),
		binary.LittleEndian.Uint32(nonce8[4:8]),
	}
	ws := make([]uint32, 16)
	copy(ws, state)
	for i := 0; i < 10; i++ {
		qr(ws, 0, 4, 8, 12); qr(ws, 1, 5, 9, 13)
		qr(ws, 2, 6, 10, 14); qr(ws, 3, 7, 11, 15)
		qr(ws, 0, 5, 10, 15); qr(ws, 1, 6, 11, 12)
		qr(ws, 2, 7, 8, 13); qr(ws, 3, 4, 9, 14)
	}
	out := make([]byte, 64)
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[4*i:], ws[i]+state[i])
	}
	return out
}

// silence unused chacha20 import (we keep it for reference / future integrity checks)
var _ = chacha20.KeySize

// ---- Portable vault: Argon2id + XChaCha20-Poly1305 AEAD (libsodium standard) ----
// Blob layout (little-endian):
//   [0:8]   magic = "1ivault\0"
//   [8]     version = 1
//   [9:12]  reserved
//   [12:24] t_cost (u32) | m_cost_KiB (u32) | parallelism (u32)
//   [24:56] Argon2id salt (32B)
//   [56:80] XChaCha20 nonce (24B)
//   [80:]   XChaCha20-Poly1305 ciphertext || 16-byte tag
const vaultMagic = "1ivault\x00"
const vaultDefaultT = 4
const vaultDefaultM = 262144 // 256 MiB in KiB
const vaultDefaultP = 1

func vaultEncrypt(plaintext, password []byte) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key := argon2.IDKey(password, salt, vaultDefaultT, vaultDefaultM, vaultDefaultP, 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)

	header := make([]byte, 80)
	copy(header[0:8], vaultMagic)
	header[8] = 1 // version
	binary.LittleEndian.PutUint32(header[12:16], vaultDefaultT)
	binary.LittleEndian.PutUint32(header[16:20], vaultDefaultM)
	binary.LittleEndian.PutUint32(header[20:24], vaultDefaultP)
	copy(header[24:56], salt)
	copy(header[56:80], nonce)
	return append(header, ct...), nil
}

func decrypt(blob, password []byte) ([]byte, error) {
	if len(blob) < headerLen+tagLen {
		return nil, fmt.Errorf("blob too short (%d bytes)", len(blob))
	}
	if string(blob[:11]) != magic {
		return nil, fmt.Errorf("bad magic: %x", blob[:11])
	}
	version := binary.LittleEndian.Uint16(blob[11:13])
	if version != 3 {
		return nil, fmt.Errorf("unsupported version %d (only v3)", version)
	}

	salt := blob[13:45]
	tCost := binary.LittleEndian.Uint32(blob[45:49])
	mCost := binary.LittleEndian.Uint32(blob[49:53])
	parallelism := binary.LittleEndian.Uint32(blob[53:57])
	nonce24 := blob[89:113]
	ctAndTag := blob[113:]
	ciphertext := ctAndTag[:len(ctAndTag)-tagLen]

	key := deriveKey(password, salt, tCost, mCost, parallelism)
	subkey := hchacha20(key, nonce24[:16])
	pt := chacha20ClassicXOR(subkey, nonce24[16:24], ciphertext, 1)
	return pt, nil
}

func readPassword() []byte {
	if pw := os.Getenv("ONEINCH_PASSWORD"); pw != "" {
		return []byte(pw)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "stdin not a terminal; set $ONEINCH_PASSWORD")
		os.Exit(1)
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read passphrase: %v\n", err)
		os.Exit(1)
	}
	return pw
}

func confirmOverwrite(path string) {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "[?] %s exists. Overwrite? [y/N] ", path)
		var ans string
		fmt.Scanln(&ans)
		if ans != "y" && ans != "Y" {
			fmt.Fprintln(os.Stderr, "[!] aborted.")
			os.Exit(4)
		}
	}
}

func main() {
	unsafePlain := flag.Bool("unsafe-plaintext", false,
		"DANGEROUS: write decrypted JSON with seeds in plaintext")
	outFlag := flag.String("o", "", "output path (default: <backup>.vault or .plaintext.json)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [flags] <backup.1inch> [password]\n"+
				"  By DEFAULT output is re-encrypted into a portable vault (.vault) using\n"+
				"  the SAME passphrase — plaintext seeds never touch the disk.\n"+
				"  Use --unsafe-plaintext to write decrypted JSON (risky).\n\n",
			os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	blob, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read blob: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("[+] blob = %d bytes\n", len(blob))

	var password []byte
	if len(args) >= 2 {
		fmt.Fprintln(os.Stderr, "[!] warning: passphrase on command line is visible via ps/history")
		password = []byte(args[1])
	} else {
		password = readPassword()
	}

	pt, err := decrypt(blob, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt: %v\n", err)
		os.Exit(3)
	}

	pt = trimNul(pt)
	var obj any
	if err := json.Unmarshal(pt, &obj); err != nil {
		// NEVER print the decrypted buffer itself — it may contain real seeds
		// even when JSON parsing fails (truncated backup, unknown subformat, …).
		fmt.Fprintln(os.Stderr, "decrypt produced non-JSON (wrong password, or backup format changed)")
		os.Exit(4)
	}
	// count wallets for user feedback
	if m, ok := obj.(map[string]any); ok {
		if accs, ok := m["accounts"].([]any); ok {
			total := 0
			for _, a := range accs {
				if ac, ok := a.(map[string]any); ok {
					if ws, ok := ac["wallets"].([]any); ok {
						total += len(ws)
					}
				}
			}
			fmt.Printf("[+] decrypted successfully — %d wallet(s)\n", total)
		}
	}
	pretty, _ := json.MarshalIndent(obj, "", "  ")

	var out string
	if *unsafePlain {
		out = *outFlag
		if out == "" {
			out = args[0] + ".plaintext.json"
		}
		fmt.Fprintln(os.Stderr, "\033[31m[!] WARNING: writing PLAINTEXT wallets to disk.\033[0m")
		fmt.Fprintln(os.Stderr, "    Any process/backup tool/user with read access CAN DRAIN these wallets.")
		fmt.Fprintf(os.Stderr, "    Shred when done: shred -uz %s\n", out)
		confirmOverwrite(out)
		if err := os.WriteFile(out, pretty, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(5)
		}
		fmt.Printf("[+] wrote %s (chmod 600, PLAINTEXT)\n", out)
	} else {
		// Re-encrypt with SAME passphrase in portable vault
		vault, err := vaultEncrypt(pretty, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vault encrypt: %v\n", err)
			os.Exit(5)
		}
		out = *outFlag
		if out == "" {
			out = args[0] + ".vault"
		}
		confirmOverwrite(out)
		if err := os.WriteFile(out, vault, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(5)
		}
		fmt.Printf("[+] wrote %s (%d bytes, chmod 600)\n", out, len(vault))
		fmt.Println("[+] re-encrypted with the SAME passphrase using portable XChaCha20-Poly1305 vault")
	}
}

func trimNul(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
