package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// keyer is everything hoot needs from the user's key: signing plus NIP-44
// (nostr.Keyer) and NIP-04 encryption. It is implemented by a local private
// key and by a NIP-46 remote signer (Amber), so DMs and zaps work the same
// either way.
type keyer interface {
	nostr.Keyer
	Encrypt04(ctx context.Context, plaintext, peer string) (string, error)
	Decrypt04(ctx context.Context, ciphertext, peer string) (string, error)
	// Remote reports whether operations go over the network (and may need
	// approval on the signer), so callers can limit how many they do.
	Remote() bool
}

var errNotSignedIn = errors.New("not signed in")

// currentKeyer returns the keyer for the signed-in user.
func currentKeyer() (keyer, error) {
	if nip46Session != nil {
		return remoteKeyer{}, nil
	}
	if localPrivateKey != "" {
		return newLocalKeyer(localPrivateKey)
	}
	return nil, errNotSignedIn
}

// localKeyer uses a private key held in memory.
type localKeyer struct{ sk, pk string }

func newLocalKeyer(sk string) (localKeyer, error) {
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return localKeyer{}, err
	}
	return localKeyer{sk: sk, pk: pk}, nil
}

func (k localKeyer) Remote() bool { return false }

func (k localKeyer) GetPublicKey(context.Context) (string, error) { return k.pk, nil }

func (k localKeyer) SignEvent(_ context.Context, ev *nostr.Event) error {
	ev.PubKey = k.pk
	return ev.Sign(k.sk)
}

func (k localKeyer) Encrypt(_ context.Context, plaintext, peer string) (string, error) {
	ck, err := nip44.GenerateConversationKey(peer, k.sk)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, ck)
}

func (k localKeyer) Decrypt(_ context.Context, ciphertext, peer string) (string, error) {
	ck, err := nip44.GenerateConversationKey(peer, k.sk)
	if err != nil {
		return "", err
	}
	return nip44.Decrypt(ciphertext, ck)
}

func (k localKeyer) Encrypt04(_ context.Context, plaintext, peer string) (string, error) {
	ss, err := nip04.ComputeSharedSecret(peer, k.sk)
	if err != nil {
		return "", err
	}
	return nip04.Encrypt(plaintext, ss)
}

func (k localKeyer) Decrypt04(_ context.Context, ciphertext, peer string) (string, error) {
	ss, err := nip04.ComputeSharedSecret(peer, k.sk)
	if err != nil {
		return "", err
	}
	return nip04.Decrypt(ciphertext, ss)
}

// remoteKeyer forwards to the NIP-46 session (looked up on each call, so a
// logout mid-operation fails cleanly instead of using a closed session).
type remoteKeyer struct{}

// remoteTimeout bounds each signer round trip (the user may need to
// approve on their phone).
const remoteTimeout = 45 * time.Second

func (remoteKeyer) Remote() bool { return true }

func session() error {
	if nip46Session == nil {
		return errNotSignedIn
	}
	return nil
}

func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, remoteTimeout)
}

func (remoteKeyer) GetPublicKey(context.Context) (string, error) {
	if err := session(); err != nil {
		return "", err
	}
	return nip46Session.UserPublicKey, nil
}

func (remoteKeyer) SignEvent(ctx context.Context, ev *nostr.Event) error {
	if err := session(); err != nil {
		return err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	ev.PubKey = nip46Session.UserPublicKey
	if err := nip46Session.SignEvent(ctx, ev); err != nil {
		return fmt.Errorf("remote signing failed: %w", err)
	}
	return nil
}

func (remoteKeyer) Encrypt(ctx context.Context, plaintext, peer string) (string, error) {
	if err := session(); err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return nip46Session.Encrypt44(ctx, peer, plaintext)
}

func (remoteKeyer) Decrypt(ctx context.Context, ciphertext, peer string) (string, error) {
	if err := session(); err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return nip46Session.Decrypt44(ctx, peer, ciphertext)
}

func (remoteKeyer) Encrypt04(ctx context.Context, plaintext, peer string) (string, error) {
	if err := session(); err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return nip46Session.Encrypt04(ctx, peer, plaintext)
}

func (remoteKeyer) Decrypt04(ctx context.Context, ciphertext, peer string) (string, error) {
	if err := session(); err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return nip46Session.Decrypt04(ctx, peer, ciphertext)
}
