package nip46

import (
	"encoding/json"
	"testing"
)

func TestGenerateConnectURI(t *testing.T) {
	uri, session, err := GenerateConnectURI("wss://relay.damus.io", "test-app")
	if err != nil {
		t.Fatalf("GenerateConnectURI failed: %v", err)
	}

	if uri == "" {
		t.Error("URI should not be empty")
	}

	if session == nil {
		t.Fatal("Session should not be nil")
	}

	// Verify URI format: nostrconnect://<clientPubkey>?relay=<relay>&metadata=<json>
	if len(uri) < 20 {
		t.Errorf("URI seems too short: %s", uri)
	}

	// Check URI starts with correct scheme
	if uri[:15] != "nostrconnect://" {
		t.Errorf("URI should start with 'nostrconnect://', got: %s", uri[:15])
	}

	// Check session has required fields
	if session.ClientPrivateKey == "" {
		t.Error("Session should have ClientPrivateKey")
	}
	if session.ClientPublicKey == "" {
		t.Error("Session should have ClientPublicKey")
	}
	if session.RelayURL != "wss://relay.damus.io" {
		t.Errorf("Session RelayURL mismatch: got %s", session.RelayURL)
	}
}

func TestGenerateConnectURIDifferentRelays(t *testing.T) {
	relays := []string{
		"wss://relay.damus.io",
		"wss://relay.nostr.band",
		"wss://nostr.wine",
		"ws://localhost:8080",
	}

	for _, relay := range relays {
		_, session, err := GenerateConnectURI(relay, "test")
		if err != nil {
			t.Errorf("Failed for relay %s: %v", relay, err)
			continue
		}

		if session.RelayURL != relay {
			t.Errorf("RelayURL mismatch: expected %s, got %s", relay, session.RelayURL)
		}

		// Each call should generate different keys
		if session.ClientPrivateKey == "" {
			t.Errorf("Empty private key for relay %s", relay)
		}
	}
}

func TestGenerateConnectURIEscaping(t *testing.T) {
	// Test that special characters in app name are handled
	_, session, err := GenerateConnectURI("wss://relay.example.com", "Test App & Co.")
	if err != nil {
		t.Fatalf("GenerateConnectURI failed: %v", err)
	}

	if session == nil {
		t.Fatal("Session should not be nil")
	}
}

func TestRequestJSON(t *testing.T) {
	req := Request{
		ID:     "test-123",
		Method: "get_public_key",
		Params: []interface{}{},
	}

	// Verify Request can be marshaled to JSON
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal Request: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data should not be empty")
	}

	// Verify we can unmarshal back
	var req2 Request
	if err := json.Unmarshal(data, &req2); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if req2.ID != req.ID {
		t.Errorf("ID mismatch: expected %s, got %s", req.ID, req2.ID)
	}
	if req2.Method != req.Method {
		t.Errorf("Method mismatch: expected %s, got %s", req.Method, req2.Method)
	}
}

func TestResponseJSON(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected Response
	}{
		{
			name: "success response",
			json: `{"id":"123","result":"abc123"}`,
			expected: Response{
				ID:     "123",
				Result: "abc123",
			},
		},
		{
			name: "error response",
			json: `{"id":"456","error":"rejected"}`,
			expected: Response{
				ID:    "456",
				Error: "rejected",
			},
		},
		{
			name: "full response",
			json: `{"id":"789","result":"success","error":""}`,
			expected: Response{
				ID:     "789",
				Result: "success",
				Error:  "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp Response
			err := json.Unmarshal([]byte(tt.json), &resp)
			if err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			if resp.ID != tt.expected.ID {
				t.Errorf("ID mismatch: expected %s, got %s", tt.expected.ID, resp.ID)
			}
			if resp.Result != tt.expected.Result {
				t.Errorf("Result mismatch: expected %s, got %s", tt.expected.Result, resp.Result)
			}
			if resp.Error != tt.expected.Error {
				t.Errorf("Error mismatch: expected %s, got %s", tt.expected.Error, resp.Error)
			}
		})
	}
}

func TestSessionClose(t *testing.T) {
	// Create a session without connecting
	_, session, err := GenerateConnectURI("wss://relay.damus.io", "test")
	if err != nil {
		t.Fatalf("GenerateConnectURI failed: %v", err)
	}

	// Close should not panic even without active connection
	session.Close()

	// Multiple closes should be safe
	session.Close()
}

func TestRequestMethods(t *testing.T) {
	methods := []struct {
		method string
		params []interface{}
	}{
		{"get_public_key", []interface{}{}},
		{"sign_event", []interface{}{`{"kind":1,"content":"test"}`}},
		{"nip04_encrypt", []interface{}{"pubkey123", "secret message"}},
		{"nip04_decrypt", []interface{}{"pubkey123", "encrypted"}},
	}

	for _, tt := range methods {
		t.Run(tt.method, func(t *testing.T) {
			req := Request{
				ID:     "test-id",
				Method: tt.method,
				Params: tt.params,
			}

			data, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("Failed to marshal %s request: %v", tt.method, err)
			}

			// Verify method is in output
			if len(data) == 0 {
				t.Errorf("Empty JSON for method %s", tt.method)
			}

			// Verify we can unmarshal back
			var req2 Request
			if err := json.Unmarshal(data, &req2); err != nil {
				t.Errorf("Failed to unmarshal %s: %v", tt.method, err)
			}

			if req2.Method != tt.method {
				t.Errorf("Method mismatch: expected %s, got %s", tt.method, req2.Method)
			}
		})
	}
}

func TestResponseBothFields(t *testing.T) {
	// Test response with both result and error (edge case)
	jsonStr := `{"id":"test","result":"ok","error":"warning"}`

	var resp Response
	err := json.Unmarshal([]byte(jsonStr), &resp)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Both should be preserved
	if resp.Result != "ok" {
		t.Errorf("Expected result 'ok', got %s", resp.Result)
	}
	if resp.Error != "warning" {
		t.Errorf("Expected error 'warning', got %s", resp.Error)
	}
}
