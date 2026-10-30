package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// Updated StoredKey includes the password hash.
type StoredKey struct {
	EncryptedKey []byte `json:"encrypted_key"`
	Salt         []byte `json:"salt"`
	// PasswordHash stores the bcrypt hash of the password.
	PasswordHash string `json:"password_hash"`
}

// hashPassword creates a bcrypt hash of the given password.
func hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// checkPassword verifies that the provided password matches the hashed one.
func checkPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func deriveKey(password []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32)
}

func encryptKey(key []byte, password []byte) (*StoredKey, error) {
	// Generate 32 random bytes for salt.
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Derive encryption key from password and salt
	derivedKey, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	// Generate 24 random bytes for nonce.
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	// Encrypt the key
	var secretKey [32]byte
	copy(secretKey[:], derivedKey[:32])
	encryptedKey := secretbox.Seal(nonce[:], key, &nonce, &secretKey)

	// Generate bcrypt hash of the password.
	pwdHash, err := hashPassword(string(password))
	if err != nil {
		return nil, err
	}

	return &StoredKey{
		EncryptedKey: encryptedKey,
		Salt:         salt,
		PasswordHash: pwdHash,
	}, nil
}

func decryptKey(storedKey *StoredKey, password []byte) ([]byte, error) {
	// Verify that the provided password matches the stored hash.
	if storedKey.PasswordHash != "" {
		if err := checkPassword(storedKey.PasswordHash, string(password)); err != nil {
			return nil, fmt.Errorf("password verification failed: %w", err)
		}
	}

	// Derive encryption key from password and salt
	derivedKey, err := deriveKey(password, storedKey.Salt)
	if err != nil {
		return nil, err
	}

	if len(storedKey.EncryptedKey) < 24+secretbox.Overhead {
		return nil, fmt.Errorf("stored key is corrupt (too short)")
	}

	// Prepare nonce and secret key
	var nonce [24]byte
	copy(nonce[:], storedKey.EncryptedKey[:24])
	var secretKey [32]byte
	copy(secretKey[:], derivedKey[:32])

	// Decrypt the key
	decryptedKey, ok := secretbox.Open(nil, storedKey.EncryptedKey[24:], &nonce, &secretKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decryptedKey, nil
}

func saveKey(key string, password []byte) error {
	// Ensure config directory exists
	configDir := getConfigDir()
	err := os.MkdirAll(configDir, 0700)
	if err != nil {
		return err
	}

	// Encrypt the key
	storedKey, err := encryptKey([]byte(key), password)
	if err != nil {
		return err
	}

	// Convert to JSON
	jsonData, err := json.Marshal(storedKey)
	if err != nil {
		return err
	}

	// Save to file
	keyPath := filepath.Join(configDir, keyFileName)
	return os.WriteFile(keyPath, jsonData, 0600)
}

func loadKey(password []byte) (string, error) {
	// Get key file path
	configDir := getConfigDir()
	keyPath := filepath.Join(configDir, keyFileName)

	// Read encrypted key
	jsonData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}

	// Unmarshal stored key
	var storedKey StoredKey
	err = json.Unmarshal(jsonData, &storedKey)
	if err != nil {
		return "", err
	}

	// Decrypt the key
	decryptedKey, err := decryptKey(&storedKey, password)
	if err != nil {
		return "", err
	}

	return string(decryptedKey), nil
}

// normalizePrivKey accepts a private key as either nsec or 64-char hex and
// returns it as hex. Keys stored via the CLI (`hoot -s -k nsec1...`) are
// saved verbatim, so anything that decrypts a stored key must go through
// this before signing.
func normalizePrivKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "nsec") {
		_, decoded, err := nip19.Decode(key)
		if err != nil {
			return "", fmt.Errorf("invalid nsec: %w", err)
		}
		sk, ok := decoded.(string)
		if !ok {
			return "", fmt.Errorf("invalid nsec payload")
		}
		return sk, nil
	}
	if !nostr.IsValid32ByteHex(key) {
		return "", fmt.Errorf("stored key is neither nsec nor 64-char hex")
	}
	return key, nil
}
