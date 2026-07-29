package main

import (
	"os"
	"path/filepath"
	"testing"
)

func resetPasswordInput(t *testing.T) {
	t.Helper()
	passwordInput.stdin = false
	passwordInput.file = ""
	t.Cleanup(func() {
		passwordInput.stdin = false
		passwordInput.file = ""
	})
}

func unsetHootPassword(t *testing.T) {
	t.Helper()
	old, set := os.LookupEnv("HOOT_PASSWORD")
	if err := os.Unsetenv("HOOT_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if set {
			_ = os.Setenv("HOOT_PASSWORD", old)
			return
		}
		_ = os.Unsetenv("HOOT_PASSWORD")
	})
}

func TestConfigurePasswordInput(t *testing.T) {
	resetPasswordInput(t)
	unsetHootPassword(t)
	args, err := configurePasswordInput([]string{"buzz", "post", "--password-stdin", "hello"})
	if err != nil {
		t.Fatalf("configurePasswordInput returned error: %v", err)
	}
	if !passwordInput.stdin {
		t.Fatal("stdin password source was not selected")
	}
	if got, want := args, []string{"buzz", "post", "hello"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("got args %q, want %q", got, want)
	}
}

func TestConfigurePasswordInputRejectsConflicts(t *testing.T) {
	resetPasswordInput(t)
	t.Setenv("HOOT_PASSWORD", "secret")
	if _, err := configurePasswordInput([]string{"--password-stdin", "buzz", "post", "hello"}); err == nil {
		t.Fatal("configurePasswordInput accepted multiple password sources")
	}
}

func TestConfigurePasswordInputRejectsRepeatedFlag(t *testing.T) {
	resetPasswordInput(t)
	unsetHootPassword(t)
	if _, err := configurePasswordInput([]string{"--password-file", "first", "--password-file", "second", "buzz", "post", "hello"}); err == nil {
		t.Fatal("configurePasswordInput accepted repeated password-file flags")
	}
}

func TestReadPasswordUsesEmptyEnvironmentValue(t *testing.T) {
	resetPasswordInput(t)
	t.Setenv("HOOT_PASSWORD", "")
	got, err := readPassword()
	if err != nil {
		t.Fatalf("readPassword returned error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty password", got)
	}
}

func TestReadPasswordFromFileTrimsSingleLineEnding(t *testing.T) {
	resetPasswordInput(t)
	unsetHootPassword(t)
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("secret\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	passwordInput.file = path
	got, err := readPassword()
	if err != nil {
		t.Fatalf("readPassword returned error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("got %q, want secret", got)
	}
}

func TestBuzzPubkeyAcceptsHex(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := buzzPubkey(key)
	if err != nil {
		t.Fatalf("buzzPubkey returned error: %v", err)
	}
	if got != key {
		t.Fatalf("got %q, want %q", got, key)
	}
}

func TestBuzzPubkeyRejectsInvalidInput(t *testing.T) {
	if _, err := buzzPubkey("not-a-pubkey"); err == nil {
		t.Fatal("buzzPubkey accepted malformed recipient")
	}
}

func TestBuzzRelayUsesEnvironment(t *testing.T) {
	t.Setenv("BUZZ_RELAY_URL", "wss://buzz.example")
	got, err := buzzRelay("")
	if err != nil {
		t.Fatalf("buzzRelay returned error: %v", err)
	}
	if got != "wss://buzz.example" {
		t.Fatalf("got %q", got)
	}
}
