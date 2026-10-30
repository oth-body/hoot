package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// Profile represents a single saved Nostr account
type Profile struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	PublicKey    string    `json:"public_key"` // hex pubkey
	EncryptedKey []byte    `json:"encrypted_key"`
	Salt         []byte    `json:"salt"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// ProfileStore holds all saved profiles and tracks last used
type ProfileStore struct {
	LastUsedProfile string              `json:"last_used_profile"`
	Profiles        map[string]*Profile `json:"profiles"`
}

// ProfileInfo is a lightweight struct for TUI display
type ProfileInfo struct {
	ID        string
	Name      string
	PublicKey string
}

// LoadProfiles loads the profile store from disk
func LoadProfiles() (*ProfileStore, error) {
	configDir := getConfigDir()
	profilesPath := filepath.Join(configDir, profilesFileName)

	data, err := os.ReadFile(profilesPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty store
			return &ProfileStore{
				Profiles: make(map[string]*Profile),
			}, nil
		}
		return nil, err
	}

	var store ProfileStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}

	if store.Profiles == nil {
		store.Profiles = make(map[string]*Profile)
	}

	return &store, nil
}

// SaveProfiles saves the profile store to disk
func SaveProfiles(store *ProfileStore) error {
	configDir := getConfigDir()
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	profilesPath := filepath.Join(configDir, profilesFileName)
	return os.WriteFile(profilesPath, data, 0600)
}

// AddProfile creates a new profile with the given name, nsec, and password
func AddProfile(name, nsec, password string) (*Profile, error) {
	// Decode nsec to get hex private key
	_, decoded, err := nip19.Decode(nsec)
	if err != nil {
		return nil, fmt.Errorf("invalid nsec: %w", err)
	}
	sk := decoded.(string)

	// Get public key
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Encrypt the private key
	storedKey, err := encryptKey([]byte(sk), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	profile := &Profile{
		ID:           generateProfileID(),
		Name:         name,
		PublicKey:    pk,
		EncryptedKey: storedKey.EncryptedKey,
		Salt:         storedKey.Salt,
		PasswordHash: storedKey.PasswordHash,
		CreatedAt:    time.Now(),
	}

	// Load existing profiles, add new one, save
	store, err := LoadProfiles()
	if err != nil {
		return nil, err
	}

	store.Profiles[profile.ID] = profile
	store.LastUsedProfile = profile.ID

	if err := SaveProfiles(store); err != nil {
		return nil, err
	}

	return profile, nil
}

// DeleteProfile removes a profile by ID
func DeleteProfile(id string) error {
	store, err := LoadProfiles()
	if err != nil {
		return err
	}

	if _, exists := store.Profiles[id]; !exists {
		return fmt.Errorf("profile not found")
	}

	delete(store.Profiles, id)

	// Clear last used if it was deleted
	if store.LastUsedProfile == id {
		store.LastUsedProfile = ""
	}

	return SaveProfiles(store)
}

// UnlockProfile unlocks a profile with the given password and returns the
// private key (always hex) and public key.
//
// Profiles created by MigrateLegacyKey have no PublicKey (it can't be
// derived without the password) and may hold an nsec rather than hex. Both
// are fixed up here on first unlock, and the derived pubkey is persisted so
// the login screen can show it next time.
func UnlockProfile(id, password string) (privateKey string, publicKey string, err error) {
	store, err := LoadProfiles()
	if err != nil {
		return "", "", err
	}

	profile, exists := store.Profiles[id]
	if !exists {
		return "", "", fmt.Errorf("profile not found")
	}

	// Create StoredKey from profile data
	storedKey := &StoredKey{
		EncryptedKey: profile.EncryptedKey,
		Salt:         profile.Salt,
		PasswordHash: profile.PasswordHash,
	}

	// Decrypt
	decrypted, err := decryptKey(storedKey, []byte(password))
	if err != nil {
		return "", "", err
	}

	sk, err := normalizePrivKey(string(decrypted))
	if err != nil {
		return "", "", err
	}
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %w", err)
	}
	profile.PublicKey = pk

	// Update last used (and persist the backfilled pubkey). Best-effort:
	// failing to write profiles.json shouldn't block login.
	store.LastUsedProfile = id
	if err := SaveProfiles(store); err != nil {
		log.Printf("Warning: failed to save profiles: %v", err)
	}

	return sk, pk, nil
}

// GetProfileList returns a list of all profiles for display
func GetProfileList() ([]ProfileInfo, string, error) {
	store, err := LoadProfiles()
	if err != nil {
		return nil, "", err
	}

	var profiles []ProfileInfo
	for _, p := range store.Profiles {
		profiles = append(profiles, ProfileInfo{
			ID:        p.ID,
			Name:      p.Name,
			PublicKey: p.PublicKey,
		})
	}

	return profiles, store.LastUsedProfile, nil
}

// MigrateLegacyKey migrates an old single-key file to the new profile system
func MigrateLegacyKey() error {
	configDir := getConfigDir()
	legacyPath := filepath.Join(configDir, keyFileName)
	profilesPath := filepath.Join(configDir, profilesFileName)

	// Check if legacy key exists and profiles don't
	if _, err := os.Stat(legacyPath); os.IsNotExist(err) {
		return nil // No legacy key to migrate
	}
	if _, err := os.Stat(profilesPath); err == nil {
		return nil // Profiles already exist, don't overwrite
	}

	// Read the legacy key file
	jsonData, err := os.ReadFile(legacyPath)
	if err != nil {
		return err
	}

	var storedKey StoredKey
	if err := json.Unmarshal(jsonData, &storedKey); err != nil {
		return err
	}

	// Create a profile from the legacy key (no pubkey available without password)
	profile := &Profile{
		ID:           generateProfileID(),
		Name:         "Default",
		PublicKey:    "", // Will be set on first unlock
		EncryptedKey: storedKey.EncryptedKey,
		Salt:         storedKey.Salt,
		PasswordHash: storedKey.PasswordHash,
		CreatedAt:    time.Now(),
	}

	store := &ProfileStore{
		LastUsedProfile: profile.ID,
		Profiles:        map[string]*Profile{profile.ID: profile},
	}

	return SaveProfiles(store)
}

// defaultProfileID picks the profile the CLI should use when there is no
// legacy key file: the last-used profile, or the only profile if there is
// exactly one. Returns "" if there is no unambiguous choice.
func defaultProfileID() string {
	store, err := LoadProfiles()
	if err != nil || len(store.Profiles) == 0 {
		return ""
	}
	if _, ok := store.Profiles[store.LastUsedProfile]; ok {
		return store.LastUsedProfile
	}
	if len(store.Profiles) == 1 {
		for id := range store.Profiles {
			return id
		}
	}
	return ""
}

// profilePublicKey returns the stored hex pubkey of a profile, or "" if the
// profile doesn't exist or has none yet (migrated legacy profiles get theirs
// on first unlock).
func profilePublicKey(id string) string {
	store, err := LoadProfiles()
	if err != nil {
		return ""
	}
	if p, ok := store.Profiles[id]; ok {
		return p.PublicKey
	}
	return ""
}

// generateProfileID creates a unique profile ID. Uses crypto/rand.Read
// (returns an error if the system entropy source fails — vanishingly
// rare but possible). On error, fall back to a timestamp-derived ID
// rather than returning "0000000000000000" (the hex of an all-zero
// buffer), which would collide with every other failed call and
// silently overwrite profiles.json entries.
func generateProfileID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is extraordinary (kernel CSPRNG down).
		// Fall back to nanosecond timestamp; not cryptographic, but
		// distinct across calls within a single process and good
		// enough to prevent collision-induced data loss.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
