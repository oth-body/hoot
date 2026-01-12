package nip46

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
)

// Session represents an active NIP-46 connection
type Session struct {
	ClientPrivateKey string
	ClientPublicKey  string
	SignerPublicKey  string
	RelayURL         string
	relay            *nostr.Relay
	UserPublicKey    string
}

// Request represents a NIP-46 JSON-RPC request
type Request struct {
	ID     string        `json:"id"`
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

// Response represents a NIP-46 JSON-RPC response
type Response struct {
	ID     string `json:"id"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// GenerateConnectURI creates a nostrconnect:// URI for QR code display
func GenerateConnectURI(relayURL string, appName string) (uri string, session *Session, err error) {
	// Generate ephemeral client keypair
	clientSK := nostr.GeneratePrivateKey()
	clientPK, err := nostr.GetPublicKey(clientSK)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get public key: %w", err)
	}

	session = &Session{
		ClientPrivateKey: clientSK,
		ClientPublicKey:  clientPK,
		RelayURL:         relayURL,
	}

	// Build URI: nostrconnect://<clientPubkey>?relay=<relay>&metadata=<json>
	metadata := map[string]string{
		"name": appName,
	}
	metadataJSON, _ := json.Marshal(metadata)

	uri = fmt.Sprintf("nostrconnect://%s?relay=%s&metadata=%s",
		clientPK,
		url.QueryEscape(relayURL),
		url.QueryEscape(string(metadataJSON)),
	)

	return uri, session, nil
}

// WaitForConnection waits for the remote signer to connect
func (s *Session) WaitForConnection(ctx context.Context) error {
	var err error
	s.relay, err = nostr.RelayConnect(ctx, s.RelayURL)
	if err != nil {
		return fmt.Errorf("failed to connect to relay: %w", err)
	}

	// Subscribe to kind 24133 events addressed to us
	filter := nostr.Filter{
		Kinds: []int{24133},
		Tags:  nostr.TagMap{"p": []string{s.ClientPublicKey}},
	}

	sub, err := s.relay.Subscribe(ctx, nostr.Filters{filter})
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	// Wait for connection event (with timeout)
	timeout := time.After(60 * time.Second)
	for {
		select {
		case ev := <-sub.Events:
			// Decrypt the content
			sharedSecret, err := nip04.ComputeSharedSecret(ev.PubKey, s.ClientPrivateKey)
			if err != nil {
				continue
			}
			decrypted, err := nip04.Decrypt(ev.Content, sharedSecret)
			if err != nil {
				continue
			}

			// Parse response
			var resp Response
			if err := json.Unmarshal([]byte(decrypted), &resp); err != nil {
				// Might be a connect acknowledgement
				s.SignerPublicKey = ev.PubKey
				return nil
			}

			// If we got a result, connection is established
			if resp.Result != "" || resp.Error == "" {
				s.SignerPublicKey = ev.PubKey
				return nil
			}

		case <-timeout:
			return fmt.Errorf("connection timeout")

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// GetPublicKey requests the user's public key from the signer
func (s *Session) GetPublicKey(ctx context.Context) (string, error) {
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())
	req := Request{
		ID:     reqID,
		Method: "get_public_key",
		Params: []interface{}{},
	}

	resp, err := s.sendRequest(ctx, req)
	if err != nil {
		return "", err
	}

	if resp.Error != "" {
		return "", fmt.Errorf("signer error: %s", resp.Error)
	}

	s.UserPublicKey = resp.Result
	return resp.Result, nil
}

// SignEvent requests the signer to sign an event
func (s *Session) SignEvent(ctx context.Context, event *nostr.Event) error {
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Serialize unsigned event
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	req := Request{
		ID:     reqID,
		Method: "sign_event",
		Params: []interface{}{string(eventJSON)},
	}

	resp, err := s.sendRequest(ctx, req)
	if err != nil {
		return err
	}

	if resp.Error != "" {
		return fmt.Errorf("signer error: %s", resp.Error)
	}

	// Parse signed event from response
	var signedEvent nostr.Event
	if err := json.Unmarshal([]byte(resp.Result), &signedEvent); err != nil {
		return fmt.Errorf("failed to parse signed event: %w", err)
	}

	// Copy signature to original event
	event.ID = signedEvent.ID
	event.Sig = signedEvent.Sig
	return nil
}

func (s *Session) sendRequest(ctx context.Context, req Request) (*Response, error) {
	if s.SignerPublicKey == "" {
		return nil, fmt.Errorf("not connected to signer")
	}

	// Serialize request
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	// Encrypt
	sharedSecret, err := nip04.ComputeSharedSecret(s.SignerPublicKey, s.ClientPrivateKey)
	if err != nil {
		return nil, err
	}
	encrypted, err := nip04.Encrypt(string(reqJSON), sharedSecret)
	if err != nil {
		return nil, err
	}

	// Create and publish event
	event := nostr.Event{
		PubKey:    s.ClientPublicKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      24133,
		Tags:      nostr.Tags{{"p", s.SignerPublicKey}},
		Content:   encrypted,
	}
	event.Sign(s.ClientPrivateKey)

	if err := s.relay.Publish(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to publish request: %w", err)
	}

	// Wait for response
	filter := nostr.Filter{
		Kinds:   []int{24133},
		Authors: []string{s.SignerPublicKey},
		Tags:    nostr.TagMap{"p": []string{s.ClientPublicKey}},
		Since:   &event.CreatedAt,
	}

	sub, err := s.relay.Subscribe(ctx, nostr.Filters{filter})
	if err != nil {
		return nil, err
	}
	defer sub.Close()

	timeout := time.After(30 * time.Second)
	for {
		select {
		case ev := <-sub.Events:
			// Decrypt
			decrypted, err := nip04.Decrypt(ev.Content, sharedSecret)
			if err != nil {
				continue
			}

			var resp Response
			if err := json.Unmarshal([]byte(decrypted), &resp); err != nil {
				continue
			}

			// Check if this is our response
			if resp.ID == req.ID || strings.HasPrefix(resp.Result, "{") || resp.Error != "" {
				return &resp, nil
			}

		case <-timeout:
			return nil, fmt.Errorf("request timeout")

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Close closes the relay connection
func (s *Session) Close() {
	if s.relay != nil {
		s.relay.Close()
	}
}
