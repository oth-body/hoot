// Package testrelay is a minimal in-memory NIP-01 relay for end-to-end tests.
//
// It supports EVENT (signature-checked, acknowledged with OK), REQ (stored
// events matching any filter, newest first, honouring limit, then EOSE) and
// CLOSE. That is enough for hoot's publish / feed / DM / profile flows to run
// against a real websocket without touching the public network.
package testrelay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/nbd-wtf/go-nostr"
)

// Relay is a running in-memory relay.
type Relay struct {
	URL string // ws://127.0.0.1:port

	srv    *httptest.Server
	mu     sync.Mutex
	events []*nostr.Event
}

// Start launches a relay on a random localhost port. Call Close when done.
func Start() *Relay {
	r := &Relay{}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	r.URL = "ws://" + strings.TrimPrefix(r.srv.URL, "http://")
	return r
}

// Close shuts the relay down.
func (r *Relay) Close() { r.srv.Close() }

// Events returns a snapshot of every stored event.
func (r *Relay) Events() []*nostr.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*nostr.Event, len(r.events))
	copy(out, r.events)
	return out
}

// Add stores ev directly, bypassing the websocket (for seeding fixtures).
// The event must already be signed.
func (r *Relay) Add(ev *nostr.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *Relay) query(f nostr.Filter) []*nostr.Event {
	r.mu.Lock()
	var matched []*nostr.Event
	for _, ev := range r.events {
		if f.Matches(ev) {
			matched = append(matched, ev)
		}
	}
	r.mu.Unlock()
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].CreatedAt > matched[j].CreatedAt })
	if f.Limit > 0 && len(matched) > f.Limit {
		matched = matched[:f.Limit]
	}
	return matched
}

func (r *Relay) serve(w http.ResponseWriter, req *http.Request) {
	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(1 << 20)
	ctx := req.Context()

	send := func(v ...any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return c.Write(ctx, websocket.MessageText, b)
	}

	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		var msg []json.RawMessage
		if err := json.Unmarshal(data, &msg); err != nil || len(msg) == 0 {
			continue
		}
		var typ string
		_ = json.Unmarshal(msg[0], &typ)

		switch typ {
		case "EVENT":
			if len(msg) < 2 {
				continue
			}
			var ev nostr.Event
			if err := json.Unmarshal(msg[1], &ev); err != nil {
				continue
			}
			if ok, _ := ev.CheckSignature(); !ok {
				_ = send("OK", ev.ID, false, "invalid: bad signature")
				continue
			}
			r.Add(&ev)
			_ = send("OK", ev.ID, true, "")

		case "REQ":
			if len(msg) < 2 {
				continue
			}
			var subID string
			_ = json.Unmarshal(msg[1], &subID)
			seen := map[string]bool{}
			for _, raw := range msg[2:] {
				var f nostr.Filter
				if err := json.Unmarshal(raw, &f); err != nil {
					continue
				}
				for _, ev := range r.query(f) {
					if seen[ev.ID] {
						continue
					}
					seen[ev.ID] = true
					_ = send("EVENT", subID, ev)
				}
			}
			_ = send("EOSE", subID)

		case "CLOSE":
			// Nothing to tear down: subscriptions don't stream live events.
		}
	}
}
