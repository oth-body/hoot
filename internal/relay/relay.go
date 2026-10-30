// Package relay is hoot's Nostr relay client.
//
// It replaces go-nostr's Relay/SimplePool for connection handling. go-nostr
// (in maintenance mode upstream) has a data race in Relay.close: it reads
// r.Connection while its own connection goroutine sets it to nil, which the
// race detector flags on every disconnect and which can, in a narrow window,
// nil-dereference. hoot still uses go-nostr for event types, signing, filters
// and the NIP-04/19/44 helpers — those are plain functions.
//
// Design: one reader goroutine per connection owns all inbound dispatch.
// Writes go straight to the websocket (coder/websocket allows concurrent
// writers). A subscription's Events channel is closed exactly once, under a
// lock that the reader also takes before sending, so a send can never race
// a close.
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/nbd-wtf/go-nostr"
)

// PingInterval is how often an idle connection is pinged. Long-lived
// subscriptions (NIP-46 pairing, NWC responses) would otherwise be dropped
// by relays or NATs that reap quiet connections.
var PingInterval = 29 * time.Second

// ErrClosed is returned for operations on a connection that has closed.
var ErrClosed = errors.New("relay connection closed")

// Relay is a connection to one relay.
type Relay struct {
	URL string

	ws     *websocket.Conn
	ctx    context.Context // cancelled when the connection ends
	cancel context.CancelCauseFunc

	mu   sync.Mutex
	subs map[string]*Subscription
	oks  map[string]chan okResult

	closeOnce sync.Once
}

type okResult struct {
	ok  bool
	msg string
}

var subCounter atomic.Uint64

// Connect dials url (normalised; "relay.example.com" becomes
// "wss://relay.example.com"). ctx bounds only the dial; the connection lives
// until Close is called or the relay drops it. If ctx has no deadline a 10s
// dial timeout applies.
func Connect(ctx context.Context, url string) (*Relay, error) {
	url = nostr.NormalizeURL(url)
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening websocket to %s: %w", url, err)
	}
	ws.SetReadLimit(32 << 20)

	connCtx, cancel := context.WithCancelCause(context.Background())
	r := &Relay{
		URL:    url,
		ws:     ws,
		ctx:    connCtx,
		cancel: cancel,
		subs:   map[string]*Subscription{},
		oks:    map[string]chan okResult{},
	}
	go r.readLoop()
	go r.pingLoop()
	return r, nil
}

// IsConnected reports whether the connection is still open.
func (r *Relay) IsConnected() bool { return r.ctx.Err() == nil }

// Context is cancelled when the connection ends; context.Cause gives why.
func (r *Relay) Context() context.Context { return r.ctx }

// Close closes the connection and every subscription on it. Safe to call
// more than once and concurrently.
func (r *Relay) Close() error {
	r.shutdown(ErrClosed)
	return nil
}

func (r *Relay) shutdown(cause error) {
	r.closeOnce.Do(func() {
		r.cancel(cause)
		_ = r.ws.Close(websocket.StatusNormalClosure, "")

		r.mu.Lock()
		subs := r.subs
		r.subs = map[string]*Subscription{}
		oks := r.oks
		r.oks = map[string]chan okResult{}
		r.mu.Unlock()

		for _, s := range subs {
			s.end(cause)
		}
		for _, ch := range oks {
			close(ch)
		}
	})
}

func (r *Relay) write(ctx context.Context, msg ...any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if !r.IsConnected() {
		return ErrClosed
	}
	if err := r.ws.Write(ctx, websocket.MessageText, b); err != nil {
		r.shutdown(fmt.Errorf("write failed: %w", err))
		return err
	}
	return nil
}

func (r *Relay) pingLoop() {
	t := time.NewTicker(PingInterval)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
			err := r.ws.Ping(ctx)
			cancel()
			if err != nil && r.IsConnected() {
				r.shutdown(fmt.Errorf("ping failed: %w", err))
				return
			}
		}
	}
}

func (r *Relay) readLoop() {
	for {
		_, data, err := r.ws.Read(r.ctx)
		if err != nil {
			r.shutdown(err)
			return
		}
		r.dispatch(data)
	}
}

func (r *Relay) dispatch(data []byte) {
	var msg []json.RawMessage
	if err := json.Unmarshal(data, &msg); err != nil || len(msg) < 2 {
		return
	}
	var typ string
	if json.Unmarshal(msg[0], &typ) != nil {
		return
	}
	str := func(i int) string {
		var s string
		if i < len(msg) {
			_ = json.Unmarshal(msg[i], &s)
		}
		return s
	}

	switch typ {
	case "EVENT":
		if len(msg) < 3 {
			return
		}
		r.mu.Lock()
		sub := r.subs[str(1)]
		r.mu.Unlock()
		if sub == nil {
			return
		}
		var ev nostr.Event
		if json.Unmarshal(msg[2], &ev) != nil {
			return
		}
		// Don't trust the relay: drop events that don't match what we
		// asked for or aren't validly signed.
		if !sub.Filters.Match(&ev) {
			return
		}
		if ok, _ := ev.CheckSignature(); !ok {
			return
		}
		sub.deliver(&ev)

	case "EOSE":
		r.mu.Lock()
		sub := r.subs[str(1)]
		r.mu.Unlock()
		if sub != nil {
			sub.eoseOnce.Do(func() { close(sub.eose) })
		}

	case "CLOSED":
		r.mu.Lock()
		sub := r.subs[str(1)]
		delete(r.subs, str(1))
		r.mu.Unlock()
		if sub != nil {
			sub.end(fmt.Errorf("relay closed subscription: %s", str(2)))
		}

	case "OK":
		if len(msg) < 3 {
			return
		}
		var ok bool
		_ = json.Unmarshal(msg[2], &ok)
		id := str(1)
		r.mu.Lock()
		ch := r.oks[id]
		delete(r.oks, id)
		r.mu.Unlock()
		if ch != nil {
			ch <- okResult{ok: ok, msg: str(3)}
			close(ch)
		}
	}
	// NOTICE, AUTH, COUNT: ignored.
}

// Publish sends ev and waits for the relay's OK. It returns an error if the
// relay rejects the event (with the relay's reason), the connection drops,
// or ctx expires first.
func (r *Relay) Publish(ctx context.Context, ev nostr.Event) error {
	ch := make(chan okResult, 1)
	r.mu.Lock()
	if !r.IsConnected() {
		r.mu.Unlock()
		return ErrClosed
	}
	r.oks[ev.ID] = ch
	r.mu.Unlock()

	if err := r.write(ctx, "EVENT", ev); err != nil {
		r.mu.Lock()
		delete(r.oks, ev.ID)
		r.mu.Unlock()
		return err
	}

	select {
	case res, open := <-ch:
		if !open {
			return fmt.Errorf("%w before %s answered", ErrClosed, r.URL)
		}
		if !res.ok {
			if res.msg == "" {
				res.msg = "rejected"
			}
			return fmt.Errorf("%s: %s", r.URL, res.msg)
		}
		return nil
	case <-ctx.Done():
		r.mu.Lock()
		delete(r.oks, ev.ID)
		r.mu.Unlock()
		return ctx.Err()
	}
}

// Subscription is a live REQ.
type Subscription struct {
	ID      string
	Filters nostr.Filters

	// Events receives matching events: stored ones first, then live ones.
	// It is closed when the subscription ends for any reason.
	Events chan *nostr.Event
	// EndOfStoredEvents is closed when the relay sends EOSE.
	EndOfStoredEvents chan struct{}

	relay    *Relay
	eose     chan struct{}
	eoseOnce sync.Once
	done     chan struct{} // closed first on end, unblocks a pending deliver
	doneOnce sync.Once
	sendMu   sync.Mutex // held while delivering; taken by end before close(Events)
	ended    bool
	err      error
}

// Subscribe sends a REQ. The subscription ends when ctx is done, Close is
// called, the relay sends CLOSED, or the connection drops.
func (r *Relay) Subscribe(ctx context.Context, filters nostr.Filters) (*Subscription, error) {
	id := strconv.FormatUint(subCounter.Add(1), 10)
	eose := make(chan struct{})
	sub := &Subscription{
		ID:                id,
		Filters:           filters,
		Events:            make(chan *nostr.Event, 64),
		EndOfStoredEvents: eose,
		relay:             r,
		eose:              eose,
		done:              make(chan struct{}),
	}

	r.mu.Lock()
	if !r.IsConnected() {
		r.mu.Unlock()
		return nil, ErrClosed
	}
	r.subs[id] = sub
	r.mu.Unlock()

	msg := []any{"REQ", id}
	for _, f := range filters {
		msg = append(msg, f)
	}
	if err := r.write(ctx, msg...); err != nil {
		r.mu.Lock()
		delete(r.subs, id)
		r.mu.Unlock()
		sub.end(err)
		return nil, err
	}

	go func() {
		select {
		case <-ctx.Done():
			sub.Close()
		case <-sub.done:
		}
	}()
	return sub, nil
}

func (s *Subscription) deliver(ev *nostr.Event) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.ended {
		return
	}
	select {
	case s.Events <- ev:
	case <-s.done:
	}
}

// end closes Events exactly once. Closing done first releases a deliver
// that is blocked on a full channel, so taking sendMu can't deadlock.
func (s *Subscription) end(err error) {
	s.doneOnce.Do(func() {
		close(s.done)
		s.sendMu.Lock()
		s.ended = true
		s.err = err
		close(s.Events)
		s.sendMu.Unlock()
	})
}

// Err reports why the subscription ended (nil while it is open or if it
// was closed with Close).
func (s *Subscription) Err() error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.err
}

// Close ends the subscription and tells the relay (CLOSE).
func (s *Subscription) Close() {
	r := s.relay
	r.mu.Lock()
	_, live := r.subs[s.ID]
	delete(r.subs, s.ID)
	r.mu.Unlock()
	if live && r.IsConnected() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = r.write(ctx, "CLOSE", s.ID)
		cancel()
	}
	s.end(nil)
}

// QueryEvents returns stored events matching filter: the channel yields
// them and is closed after EOSE (or when ctx ends / the relay drops).
func (r *Relay) QueryEvents(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
	sub, err := r.Subscribe(ctx, nostr.Filters{filter})
	if err != nil {
		return nil, err
	}
	out := make(chan *nostr.Event)
	go func() {
		defer close(out)
		defer sub.Close()
		for {
			select {
			case ev, ok := <-sub.Events:
				if !ok {
					return
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			case <-sub.EndOfStoredEvents:
				// Drain anything already buffered, then stop.
				for {
					select {
					case ev, ok := <-sub.Events:
						if !ok {
							return
						}
						select {
						case out <- ev:
						case <-ctx.Done():
							return
						}
					default:
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
