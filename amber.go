package main

// Remembering an Amber (NIP-46) pairing so the next launch can reconnect
// without scanning a QR code.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"hoot/nip46"
)

const amberSessionFile = "amber_session.json"

// amberResumeTimeout bounds reconnecting (the user may need to open Amber).
var amberResumeTimeout = 60 * time.Second

// savedAmber is what's stored. ClientSecret is the NIP-46 client key the
// signer authorised: anyone holding it can send this signer requests (which
// the signer may still ask to approve), so the file is 0600 and can be
// forgotten from the login screen.
type savedAmber struct {
	ClientSecret string    `json:"client_secret"`
	SignerPubKey string    `json:"signer_pubkey"`
	UserPubKey   string    `json:"user_pubkey"`
	Relays       []string  `json:"relays"`
	Name         string    `json:"name,omitempty"`
	SavedAt      time.Time `json:"saved_at"`
}

func amberSessionPath() string { return filepath.Join(getConfigDir(), amberSessionFile) }

func saveAmberSession(s *nip46.Session, name string) error {
	if s == nil || s.SignerPublicKey == "" || s.UserPublicKey == "" {
		return errors.New("session is not paired")
	}
	data, err := json.MarshalIndent(savedAmber{
		ClientSecret: s.ClientPrivateKey,
		SignerPubKey: s.SignerPublicKey,
		UserPubKey:   s.UserPublicKey,
		Relays:       s.RelayURLs,
		Name:         name,
		SavedAt:      time.Now(),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(getConfigDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(amberSessionPath(), data, 0600)
}

func loadAmberSession() (*savedAmber, error) {
	data, err := os.ReadFile(amberSessionPath())
	if err != nil {
		return nil, err
	}
	var sv savedAmber
	if err := json.Unmarshal(data, &sv); err != nil {
		return nil, fmt.Errorf("saved Amber session is corrupt: %w", err)
	}
	return &sv, nil
}

func forgetAmberSession() error {
	err := os.Remove(amberSessionPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// savedAmberLabel is the login-menu label for the saved session, if any.
func savedAmberLabel() (string, bool) {
	sv, err := loadAmberSession()
	if err != nil {
		return "", false
	}
	if sv.Name != "" {
		return sv.Name, true
	}
	return shortKey(sv.UserPubKey), true
}

// resumeAmber reconnects the saved session and confirms the signer answers
// for the same account. On success it becomes the active signing session.
func resumeAmber() (string, *nip46.ProfileMetadata, error) {
	sv, err := loadAmberSession()
	if err != nil {
		return "", nil, fmt.Errorf("no saved Amber session")
	}
	sess, err := nip46.ResumeSession(sv.ClientSecret, sv.SignerPubKey, sv.UserPubKey, sv.Relays)
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), amberResumeTimeout)
	defer cancel()
	if err := sess.ConnectRelays(ctx); err != nil {
		return "", nil, err
	}
	pk, err := sess.GetPublicKey(ctx)
	if err != nil {
		sess.Close()
		return "", nil, fmt.Errorf("Amber didn't answer (%v). Open Amber on your phone and try again, or scan a new QR code", err)
	}
	if pk != sv.UserPubKey {
		sess.Close()
		return "", nil, fmt.Errorf("Amber answered for a different account; scan a new QR code")
	}

	endRemoteSession()
	localPrivateKey = ""
	nip46Session = sess

	pctx, pcancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer pcancel()
	profile, _ := sess.FetchProfile(pctx, pk)
	return pk, profile, nil
}
