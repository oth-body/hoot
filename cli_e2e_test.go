package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"hoot/internal/testrelay"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// TestCLIEndToEndAgainstLocalRelay runs the compiled hoot binary through the
// main CLI flows — store key, post, list posts, update profile, view profile —
// against an in-process relay, so nothing touches the public network.
func TestCLIEndToEndAgainstLocalRelay(t *testing.T) {
	relay := testrelay.Start()
	defer relay.Close()

	home := t.TempDir()
	cfgDir := filepath.Join(home, "hoot")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Linux/BSD use XDG_CONFIG_HOME, macOS $HOME/Library/Application Support,
	// Windows %APPDATA%; write relays.txt everywhere hoot might look.
	for _, d := range []string{cfgDir, filepath.Join(home, "Library", "Application Support", "hoot")} {
		_ = os.MkdirAll(d, 0700)
		if err := os.WriteFile(filepath.Join(d, "relays.txt"), []byte(relay.URL+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	workDir := t.TempDir() // keep the repo's ./relays.txt out of the way

	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(binaryPath, args...)
		cmd.Dir = workDir
		cmd.Env = append(os.Environ(),
			"HOME="+home, "XDG_CONFIG_HOME="+home, "APPDATA="+home,
			"HOOT_PASSWORD=e2e-pass")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("hoot %v: %v\n%s", args, err, out)
		}
		return string(out)
	}

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	nsec, _ := nip19.EncodePrivateKey(sk)

	run("-s", "-k", nsec)

	out := run("-m", "hello relay #hoot")
	if !strings.Contains(out, "Successfully published") {
		t.Fatalf("post output: %s", out)
	}
	evs := relay.Events()
	if len(evs) != 1 || evs[0].PubKey != pk || evs[0].Kind != 1 {
		t.Fatalf("relay events after post: %+v", evs)
	}

	if out := run("-l"); !strings.Contains(out, "hello relay #hoot") {
		t.Fatalf("-l output missing post:\n%s", out)
	}

	run("-u", `{"name":"e2e-owl","about":"testing"}`)
	if out := run("-p"); !strings.Contains(out, `"name":"e2e-owl"`) {
		t.Fatalf("-p output missing updated profile:\n%s", out)
	}
}
