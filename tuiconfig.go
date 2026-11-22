package main

import (
	"context"
	"fmt"
	"hoot/nip46"
	"hoot/tui"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// tuiConfig wires the TUI's callbacks to hoot's key, profile, relay, posting,
// reading, NIP-46 and tipping functions.
func tuiConfig() tui.Config {
	return tui.Config{
		HasKey: func() bool {
			configDir := getConfigDir()
			keyPath := filepath.Join(configDir, keyFileName)
			_, err := os.Stat(keyPath)
			return !os.IsNotExist(err)
		},
		OnLoadKey: func(password string) (string, string, error) {
			privKey, err := loadKey([]byte(password))
			if err != nil {
				return "", "", err
			}
			sk, err := normalizePrivKey(privKey)
			if err != nil {
				return "", "", err
			}
			pk, err := nostr.GetPublicKey(sk)
			if err != nil {
				return "", "", err
			}
			// Cache for posting
			useLocalKey(sk)
			return sk, pk, nil
		},
		OnResetKey: func() error {
			configDir := getConfigDir()
			keyPath := filepath.Join(configDir, keyFileName)
			return os.Remove(keyPath)
		},
		OnLogin: func(nsec string, password string, save bool) (string, error) {
			_, decoded, err := nip19.Decode(nsec)
			if err != nil {
				return "", err
			}
			sk := decoded.(string)
			pk, err := nostr.GetPublicKey(sk)
			if err != nil {
				return "", err
			}

			if save {
				if err := saveKey(sk, []byte(password)); err != nil {
					return "", err
				}
			}

			// Cache for posting
			useLocalKey(sk)
			return pk, nil
		},
		OnPost:              publishPostTUI,
		OnLoadFeed:          func() ([]tui.FeedPost, error) { return getFeedPosts(false) },
		OnLoadFollowingFeed: func() ([]tui.FeedPost, error) { return getFeedPosts(true) },
		OnLoadDMs:           getDMs,
		OnLoadReplies:       getReactions,
		OnLoadRelays: func() ([]string, error) {
			return loadRelays() // Uses existing helper
		},
		OnSaveRelays: func(relays []string) error {
			configDir := getConfigDir()
			relayPath := filepath.Join(configDir, "relays.txt")
			// Ensure directory exists
			if err := os.MkdirAll(configDir, 0700); err != nil {
				return err
			}
			data := strings.Join(relays, "\n")
			return os.WriteFile(relayPath, []byte(data), 0600)
		},
		OnInitQR: func() (string, error) {
			// Advertise only the two known-good fallback relays in
			// the QR. Every relay in the URI is one Amber will open
			// a WebSocket to; a flaky relay in the list produces a
			// "expected 101, got 503" error in Amber even though the
			// ack arrives through a healthy relay. hoot still dials
			// and subscribes to ALL configured relays plus the
			// fallbacks, so the connect ack is never missed.
			//
			// Set HOOT_ADVERTISE_ALL_RELAYS=1 to also advertise the
			// configured relays (e.g. for a private relay setup).
			userRelays := getRelayList()
			// Drop any previous session (and local key) first so a
			// retried scan doesn't leak relay connections.
			endRemoteSession()
			localPrivateKey = ""
			uri, session, err := nip46.GenerateConnectURI(nip46.AdvertisedRelays(userRelays), "Hoot")
			if err != nil {
				return "", err
			}
			session.SetListenRelays(nip46.PairingRelays(userRelays))
			// Dial and subscribe in the background of this cmd.
			ctx := context.Background()
			if err := session.ConnectRelays(ctx); err != nil {
				return "", fmt.Errorf("relay connect: %w", err)
			}
			nip46Session = session
			return uri, nil
		},
		OnCheckQR: func() (string, *nip46.ProfileMetadata, error) {
			if nip46Session == nil {
				return "", nil, fmt.Errorf("session not initialized")
			}
			// Short poll — the subscriptions are already active
			// from ConnectRelays called in OnInitQR. We just
			// check if the signer's connect event arrived yet.
			pubKey, err := nip46Session.CheckConnection(3 * time.Second)
			if err != nil {
				return "", nil, err // TUI will retry
			}

			// Got connect — now request the user's public key.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			userPubKey, err := nip46Session.GetPublicKey(ctx)
			if err != nil {
				return pubKey, nil, nil // fall back to signer pubkey
			}

			// Fetch the user's kind-0 profile metadata so the
			// home screen can render their name + about + nip-05
			// instead of just a 16-char pubkey prefix. Failure
			// here is non-fatal: many users have no profile, and
			// the caller falls back to the npub display.
			profileCtx, profileCancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer profileCancel()
			profile, _ := nip46Session.FetchProfile(profileCtx, userPubKey)
			if profile != nil && eventCache != nil {
				// Cache the freshly-fetched profile so subsequent
				// logins can render the name immediately without
				// hitting the relays again. 24h TTL matches the
				// profile event re-publish cadence most signers
				// use (kind 0 is replaceable).
				_ = eventCache.StoreProfile(
					profile.PubKey,
					profile.Name,
					profile.About,
					profile.Picture,
					profile.NIP05,
					time.Now().Unix(),
					24*time.Hour,
				)
			}
			// Remember the pairing so next time "Continue as …" works
			// without a QR scan (best effort).
			name := ""
			if profile != nil {
				name = profile.Name
			}
			if err := saveAmberSession(nip46Session, name); err != nil {
				log.Printf("Warning: couldn't save Amber session: %v", err)
			}
			return userPubKey, profile, nil
		},
		// Profile callbacks
		OnListProfiles: func() ([]tui.ProfileInfo, string, error) {
			profiles, lastUsed, err := GetProfileList()
			if err != nil {
				return nil, "", err
			}
			// Convert to TUI ProfileInfo
			var tuiProfiles []tui.ProfileInfo
			for _, p := range profiles {
				tuiProfiles = append(tuiProfiles, tui.ProfileInfo{
					ID:        p.ID,
					Name:      p.Name,
					PublicKey: p.PublicKey,
				})
			}
			return tuiProfiles, lastUsed, nil
		},
		OnSelectProfile: func(id, password string) (string, string, error) {
			privKey, pubKey, err := UnlockProfile(id, password)
			if err != nil {
				return "", "", err
			}
			// Cache for posting
			useLocalKey(privKey)
			return privKey, pubKey, nil
		},
		OnAddProfile: func(name, nsec, password string) (string, string, error) {
			profile, err := AddProfile(name, nsec, password)
			if err != nil {
				return "", "", err
			}
			sk, err := normalizePrivKey(nsec)
			if err != nil {
				return "", "", err
			}
			// Cache the private key for posting
			useLocalKey(sk)
			return sk, profile.PublicKey, nil
		},
		OnDeleteProfile: DeleteProfile,
		OnTip: func(target string, sats int64) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			res, err := tipUser(ctx, target, sats, nil)
			if err != nil {
				return "", err
			}
			return res.String(), nil
		},
		OnSavedAmber:  savedAmberLabel,
		OnResumeAmber: resumeAmber,
		OnForgetAmber: forgetAmberSession,
		OnSendDM:      sendDM,
		OnReply:       publishReply,
		OnReact:       publishReaction,
		OnZap: func(pubkey, eventID string, sats int64) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			res, err := zapUser(ctx, pubkey, eventID, sats, "")
			if err != nil {
				return "", err
			}
			if !res.Zapped {
				return res.String() + " (their address doesn't support zaps, so it was sent as a plain tip)", nil
			}
			return res.String(), nil
		},
		OnLogout: func() {
			endRemoteSession()
			localPrivateKey = ""
		},
	}
}
