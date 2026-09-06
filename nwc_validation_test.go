package main

import (
	"strings"
	"testing"
)

// TestValidateNWCURI pins the structure check that runs before saving
// a NWC connection string. Without this, `hoot -nwc garbage` silently
// wrote garbage to disk and only failed later (less actionable error).
// With this, the user gets immediate feedback on a malformed URI.
func TestValidateNWCURI(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		wantError bool
		wantMsg   string // substring expected in the error message (when wantError)
	}{
		{
			name:      "empty URI is rejected",
			uri:       "",
			wantError: true,
			wantMsg:   "must not be empty",
		},
		{
			name:      "wrong scheme is rejected",
			uri:       "https://example.com",
			wantError: true,
			wantMsg:   "scheme must be nostr+walletconnect",
		},
		{
			name:      "missing pubkey in authority is rejected",
			uri:       "nostr+walletconnect://?relay=wss://r&secret=abc",
			wantError: true,
			wantMsg:   "wallet pubkey",
		},
		{
			name:      "missing relay param is rejected",
			uri:       "nostr+walletconnect://pubkey?secret=abc",
			wantError: true,
			wantMsg:   "?relay=",
		},
		{
			name:      "missing secret param is rejected",
			uri:       "nostr+walletconnect://pubkey?relay=wss://r",
			wantError: true,
			wantMsg:   "?secret=",
		},
		{
			name: "valid NWC URI is accepted",
			uri:  "nostr+walletconnect://pubkey123?relay=wss%3A%2F%2Frelay.example.com&secret=hexsecret",
		},
		{
			name: "valid NWC URI with extra params is accepted",
			uri:  "nostr+walletconnect://pubkey123?relay=wss%3A%2F%2Frelay.example.com&secret=hexsecret&lud16=alice%40example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNWCURI(tt.uri)
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error for URI %q, got nil", tt.uri)
					return
				}
				if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("expected error containing %q, got: %v", tt.wantMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error for URI %q, got: %v", tt.uri, err)
				}
			}
		})
	}
}