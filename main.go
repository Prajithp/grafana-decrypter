// Command secretdecrypt decrypts Grafana datasource secure_json_data values
// that were encrypted using Grafana's envelope encryption (AES-256-CFB).
//
// It supports two modes:
//   - Legacy mode: ciphertext encrypted directly with the secret_key (no envelope prefix).
//   - Envelope mode: ciphertext prefixed with #<base64-data-key-id># where the DEK
//     is itself encrypted with the secret_key via AES-256-CFB + PBKDF2.
//
// Usage:
//
//	go run ./tools/secretdecrypt \
//	  -secret-key <grafana_secret_key> \
//	  -ciphertext <hex-or-base64-encoded ciphertext> \
//	  [-encrypted-dek <hex-encoded encrypted DEK from data_keys table>] \
//	  [-encoding hex|base64]
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	saltLength                   = 8
	encryptionAlgorithmDelimiter = '*'
)

func main() {
	secretKey := flag.String("secret-key", "", "Grafana secret_key from [security] config (required)")
	cipherHex := flag.String("ciphertext", "", "Encrypted value from secure_json_data column (hex or base64, required)")
	encryptedDEK := flag.String("encrypted-dek", "", "Encrypted data encryption key from data_keys.encrypted_data (hex). Required for envelope-encrypted values")
	encoding := flag.String("encoding", "hex", "Encoding of -ciphertext input: hex or base64")
	flag.Parse()

	if *secretKey == "" || *cipherHex == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Decode ciphertext input.
	blob, err := decodeInput(*cipherHex, *encoding)
	if err != nil {
		fatal("decoding ciphertext: %v", err)
	}

	// Determine legacy vs envelope encryption.
	// Envelope-encrypted blobs start with '#'.
	if len(blob) > 0 && blob[0] == '#' {
		decryptEnvelope(blob, *secretKey, *encryptedDEK)
	} else {
		decryptLegacy(blob, *secretKey)
	}
}

// decryptLegacy handles values encrypted directly with the secret_key (no envelope).
func decryptLegacy(blob []byte, secretKey string) {
	plaintext, err := decryptAES(blob, secretKey)
	if err != nil {
		fatal("legacy decrypt: %v", err)
	}
	fmt.Println(string(plaintext))
}

// decryptEnvelope handles envelope-encrypted values: #<b64-key-id>#<aes-cfb payload>.
// The DEK must be supplied via -encrypted-dek and is itself decrypted with the secret_key.
func decryptEnvelope(blob []byte, secretKey, encDEKHex string) {
	// Strip leading '#'.
	blob = blob[1:]

	// Find closing '#'.
	idx := indexOf(blob, '#')
	if idx == -1 {
		fatal("envelope: could not find key-id delimiter in ciphertext")
	}

	keyIDB64 := blob[:idx]
	payload := blob[idx+1:]

	keyID := make([]byte, base64.RawStdEncoding.DecodedLen(len(keyIDB64)))
	n, err := base64.RawStdEncoding.Decode(keyID, keyIDB64)
	if err != nil {
		fatal("envelope: decoding key id: %v", err)
	}
	keyID = keyID[:n]

	fmt.Fprintf(os.Stderr, "Data key ID: %s\n", string(keyID))

	if encDEKHex == "" {
		fatal("envelope encryption detected — you must supply -encrypted-dek (from data_keys.encrypted_data for key %q)", string(keyID))
	}

	// Decrypt the DEK using the secret_key.
	encDEK, err := hex.DecodeString(encDEKHex)
	if err != nil {
		fatal("decoding encrypted DEK hex: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Decrypting DEK...\n")
	dek, err := decryptAES(encDEK, secretKey)
	if err != nil {
		fatal("decrypting DEK: %v", err)
	}

	fmt.Fprintf(os.Stderr, "DEK decrypted successfully (%d bytes)\n", len(dek))

	// Decrypt the actual payload with the DEK.
	fmt.Fprintf(os.Stderr, "Decrypting payload...\n")
	plaintext, err := decryptAES(payload, string(dek))
	if err != nil {
		fatal("decrypting payload with DEK: %v", err)
	}
	fmt.Println(string(plaintext))
}

// stripAlgorithmPrefix strips the *<base64(algorithm)>* prefix that Grafana's
// encryption service prepends to every ciphertext. Returns the algorithm name
// and the raw AES payload. If no prefix is found, assumes aes-cfb (legacy).
func stripAlgorithmPrefix(blob []byte) (algorithm string, payload []byte) {
	if len(blob) == 0 || blob[0] != encryptionAlgorithmDelimiter {
		return "aes-cfb", blob
	}

	rest := blob[1:]
	idx := indexOf(rest, encryptionAlgorithmDelimiter)
	if idx == -1 {
		return "aes-cfb", blob
	}

	algB64 := rest[:idx]
	algBytes := make([]byte, base64.RawStdEncoding.DecodedLen(len(algB64)))
	n, err := base64.RawStdEncoding.Decode(algBytes, algB64)
	if err != nil || n == 0 {
		return "aes-cfb", blob
	}

	return string(algBytes[:n]), rest[idx+1:]
}

// decryptAES decrypts a blob that may have a *<b64-algorithm>* prefix,
// using Grafana's AES-256-CFB (or AES-256-GCM) scheme:
//
//	layout after prefix: [salt 8 bytes] [IV 16 bytes] [ciphertext...]
//	key derivation: PBKDF2-SHA256(secret, salt, 10000 iterations, 32-byte key)
func decryptAES(blob []byte, secret string) ([]byte, error) {
	algorithm, blob := stripAlgorithmPrefix(blob)
	fmt.Fprintf(os.Stderr, "Algorithm: %s\n", algorithm)

	switch algorithm {
	case "aes-cfb":
		return decryptAESCFB(blob, secret)
	case "aes-gcm":
		return decryptAESGCM(blob, secret)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// decryptAESCFB decrypts a raw AES-256-CFB blob (no algorithm prefix):
//
//	layout: [salt 8 bytes] [IV 16 bytes] [ciphertext...]
func decryptAESCFB(blob []byte, secret string) ([]byte, error) {
	if len(blob) < saltLength {
		return nil, fmt.Errorf("payload too short for salt (len=%d)", len(blob))
	}

	salt := blob[:saltLength]
	key, err := pbkdf2.Key(sha256.New, secret, salt, 10000, 32)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2 key derivation: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	if len(blob) < saltLength+aes.BlockSize {
		return nil, fmt.Errorf("payload too short for IV (len=%d)", len(blob))
	}

	iv := blob[saltLength : saltLength+aes.BlockSize]
	ciphertext := blob[saltLength+aes.BlockSize:]
	plaintext := make([]byte, len(ciphertext))

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// decryptAESGCM decrypts a raw AES-256-GCM blob (no algorithm prefix):
//
//	layout: [salt 8 bytes] [nonce 12 bytes] [ciphertext+tag...]
func decryptAESGCM(blob []byte, secret string) ([]byte, error) {
	if len(blob) < saltLength {
		return nil, fmt.Errorf("payload too short for salt (len=%d)", len(blob))
	}

	salt := blob[:saltLength]
	key, err := pbkdf2.Key(sha256.New, secret, salt, 10000, 32)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2 key derivation: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}

	nonceEnd := saltLength + gcm.NonceSize()
	if len(blob) < nonceEnd {
		return nil, fmt.Errorf("payload too short for nonce (len=%d)", len(blob))
	}

	nonce := blob[saltLength:nonceEnd]
	ciphertext := blob[nonceEnd:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func decodeInput(input, encoding string) ([]byte, error) {
	input = strings.TrimSpace(input)
	switch encoding {
	case "hex":
		return hex.DecodeString(input)
	case "base64":
		return base64.StdEncoding.DecodeString(input)
	default:
		return nil, fmt.Errorf("unsupported encoding %q (use hex or base64)", encoding)
	}
}

func indexOf(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
