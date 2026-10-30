package main

import (
	"context"
	"fmt"
	"hoot/nip46"
	"hoot/tui"
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
			// Generate NIP-46 URI with ALL configured relays AND
			// a hard-coded set of relays Amber is known to publish
			// to (relay.damus.io, nostr.wine). The latter covers
			// the common failure mode where the user's relays.txt
			// is sparse or contains relays Amber doesn't recognise
			// — Amber then publishes to its own preferred relay
			// instead of the URI's, and hoot's subscription (only
			// on the user's relays) never sees the connect ack.
			//
			// See nip46.PairingRelays for the full rationale.
			userRelays := getRelayList()
			// Drop any previous session (and local key) first so a
			// retried scan doesn't leak relay connections.
			endRemoteSession()
			localPrivateKey = ""
			uri, session, err := nip46.GenerateConnectURI(nip46.PairingRelays(userRelays), "Hoot")
			if err != nil {
				return "", err
			}
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
		OnLogout: func() {
			endRemoteSession()
			localPrivateKey = ""
		},
	}
}
