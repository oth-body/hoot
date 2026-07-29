package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/keyer"
	"github.com/nbd-wtf/go-nostr/nip17"
	"github.com/nbd-wtf/go-nostr/nip19"
)

const buzzDefaultTimeout = 20 * time.Second

// buzzClient authenticates as the user's long-lived Nostr identity whenever a
// relay requests NIP-42 authentication. This is required by Buzz for protected
// subscriptions and gift-wrapped DMs.
func buzzClient(ctx context.Context, privateKey string) (*nostr.SimplePool, keyer.KeySigner, error) {
	signer, err := keyer.NewPlainKeySigner(privateKey)
	if err != nil {
		return nil, keyer.KeySigner{}, fmt.Errorf("create Nostr signer: %w", err)
	}
	pool := nostr.NewSimplePool(ctx, nostr.WithAuthHandler(func(ctx context.Context, auth nostr.RelayEvent) error {
		return signer.SignEvent(ctx, auth.Event)
	}))
	return pool, signer, nil
}

func buzzRelay(flagValue string) (string, error) {
	relay := strings.TrimSpace(flagValue)
	if relay == "" {
		relay = strings.TrimSpace(os.Getenv("BUZZ_RELAY_URL"))
	}
	if !strings.HasPrefix(relay, "wss://") && !strings.HasPrefix(relay, "ws://") {
		return "", errors.New("a ws:// or wss:// Buzz relay URL is required (use --relay or BUZZ_RELAY_URL)")
	}
	return relay, nil
}

func buzzPubkey(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if len(value) == 64 {
		for _, c := range value {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return "", errors.New("recipient pubkey must be hex or npub")
			}
		}
		return value, nil
	}
	prefix, decoded, err := nip19.Decode(value)
	if err != nil || prefix != "npub" {
		return "", errors.New("recipient pubkey must be a 64-character hex key or npub")
	}
	pubkey, ok := decoded.(string)
	if !ok || len(pubkey) != 64 {
		return "", errors.New("invalid npub recipient")
	}
	return pubkey, nil
}

func buzzPrivateKey() (string, error) {
	password, err := readPassword()
	if err != nil {
		return "", err
	}
	privateKey, _, err := loadAndDecodeKey(password)
	if err != nil {
		return "", fmt.Errorf("load identity: %w", err)
	}
	return privateKey, nil
}

func publishBuzzChannelMessage(ctx context.Context, relayURL, privateKey, channelID, content, replyTo string) error {
	if strings.TrimSpace(channelID) == "" {
		return errors.New("--channel is required")
	}
	if strings.TrimSpace(content) == "" {
		return errors.New("message cannot be empty")
	}
	pool, signer, err := buzzClient(ctx, privateKey)
	if err != nil {
		return err
	}
	defer pool.Close("command completed")

	event := nostr.Event{Kind: nostr.KindTextNote, Content: content, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"h", channelID}}}
	if replyTo != "" {
		event.Tags = append(event.Tags, nostr.Tag{"e", replyTo, "", "reply"})
	}
	if err := signer.SignEvent(ctx, &event); err != nil {
		return fmt.Errorf("sign channel message: %w", err)
	}
	return publishBuzzEvent(ctx, pool, signer, relayURL, event)
}

func publishBuzzEvent(ctx context.Context, pool *nostr.SimplePool, signer keyer.KeySigner, relayURL string, event nostr.Event) error {
	relay, err := pool.EnsureRelay(relayURL)
	if err != nil {
		return fmt.Errorf("connect to Buzz relay: %w", err)
	}
	if err := relay.Publish(ctx, event); err != nil {
		if !strings.Contains(err.Error(), "auth-required:") {
			return fmt.Errorf("publish event: %w", err)
		}
		if err := relay.Auth(ctx, func(event *nostr.Event) error { return signer.SignEvent(ctx, event) }); err != nil {
			return fmt.Errorf("authenticate to Buzz relay: %w", err)
		}
		if err := relay.Publish(ctx, event); err != nil {
			return fmt.Errorf("publish channel message after authentication: %w", err)
		}
	}
	return nil
}

func publishBuzzDM(ctx context.Context, relayURL, privateKey, recipient, content string) error {
	if strings.TrimSpace(content) == "" {
		return errors.New("message cannot be empty")
	}
	pool, signer, err := buzzClient(ctx, privateKey)
	if err != nil {
		return err
	}
	defer pool.Close("command completed")

	// Buzz does not implement kind:10050 relay lists. Publish both the recipient
	// wrap and our encrypted history copy to the selected Buzz relay. We publish
	// explicitly rather than using nip17.PublishMessage so NIP-42 is also retried
	// for a relay that prefixes its rejection with "msg: ".
	toUs, toThem, err := nip17.PrepareMessage(ctx, content, nil, signer, recipient, nil)
	if err != nil {
		return fmt.Errorf("prepare NIP-17 DM: %w", err)
	}
	if err := publishBuzzEvent(ctx, pool, signer, relayURL, toUs); err != nil {
		return fmt.Errorf("publish NIP-17 self copy: %w", err)
	}
	if err := publishBuzzEvent(ctx, pool, signer, relayURL, toThem); err != nil {
		return fmt.Errorf("publish NIP-17 recipient copy: %w", err)
	}
	return nil
}

func runBuzzCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: hoot buzz <post|dm> [options] <message>")
	}
	switch args[0] {
	case "post":
		flags := flag.NewFlagSet("buzz post", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		relay := flags.String("relay", "", "Buzz relay WebSocket URL")
		channel := flags.String("channel", "", "Buzz channel UUID")
		reply := flags.String("reply-to", "", "parent event id for a NIP-10 reply")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() == 0 {
			return errors.New("buzz post requires a message")
		}
		relayURL, err := buzzRelay(*relay)
		if err != nil {
			return err
		}
		privateKey, err := buzzPrivateKey()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), buzzDefaultTimeout)
		defer cancel()
		return publishBuzzChannelMessage(ctx, relayURL, privateKey, *channel, strings.Join(flags.Args(), " "), *reply)
	case "dm":
		flags := flag.NewFlagSet("buzz dm", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		relay := flags.String("relay", "", "Buzz relay WebSocket URL")
		to := flags.String("to", "", "recipient npub or 64-character hex pubkey")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() == 0 {
			return errors.New("buzz dm requires a message")
		}
		relayURL, err := buzzRelay(*relay)
		if err != nil {
			return err
		}
		recipient, err := buzzPubkey(*to)
		if err != nil {
			return err
		}
		privateKey, err := buzzPrivateKey()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), buzzDefaultTimeout)
		defer cancel()
		return publishBuzzDM(ctx, relayURL, privateKey, recipient, strings.Join(flags.Args(), " "))
	default:
		return fmt.Errorf("unknown buzz subcommand: %s", args[0])
	}
}
