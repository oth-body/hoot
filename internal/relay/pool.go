package relay

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/nbd-wtf/go-nostr"
)

// QueryAll asks every relay in urls for events matching filters, in
// parallel, and returns the union de-duplicated by ID and sorted newest
// first. Relays that can't be reached or don't answer before ctx ends are
// skipped; failures maps each such URL to its error.
func QueryAll(ctx context.Context, urls []string, filters ...nostr.Filter) (events []*nostr.Event, failures map[string]error) {
	type result struct {
		url    string
		events []*nostr.Event
		err    error
	}
	results := make(chan result, len(urls))
	var wg sync.WaitGroup
	for _, u := range dedupe(urls) {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			r, err := Connect(ctx, u)
			if err != nil {
				results <- result{url: u, err: err}
				return
			}
			defer r.Close()
			var got []*nostr.Event
			for _, f := range filters {
				ch, err := r.QueryEvents(ctx, f)
				if err != nil {
					results <- result{url: u, events: got, err: err}
					return
				}
				for ev := range ch {
					got = append(got, ev)
				}
			}
			results <- result{url: u, events: got}
		}(u)
	}
	wg.Wait()
	close(results)

	failures = map[string]error{}
	seen := map[string]bool{}
	for res := range results {
		if res.err != nil {
			failures[res.url] = res.err
		}
		for _, ev := range res.events {
			if !seen[ev.ID] {
				seen[ev.ID] = true
				events = append(events, ev)
			}
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].CreatedAt > events[j].CreatedAt })
	return events, failures
}

// PublishAll sends ev to every relay in urls in parallel. accepted lists
// the relays that acknowledged it; failures maps the rest to their error.
// It returns an error only if no relay accepted the event.
func PublishAll(ctx context.Context, urls []string, ev nostr.Event) (accepted []string, failures map[string]error, err error) {
	type result struct {
		url string
		err error
	}
	urls = dedupe(urls)
	results := make(chan result, len(urls))
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			r, err := Connect(ctx, u)
			if err != nil {
				results <- result{u, err}
				return
			}
			defer r.Close()
			results <- result{u, r.Publish(ctx, ev)}
		}(u)
	}
	wg.Wait()
	close(results)

	failures = map[string]error{}
	for res := range results {
		if res.err != nil {
			failures[res.url] = res.err
		} else {
			accepted = append(accepted, res.url)
		}
	}
	sort.Strings(accepted)
	if len(accepted) == 0 {
		return nil, failures, errors.New("failed to publish to any relay")
	}
	return accepted, failures, nil
}

func dedupe(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		n := nostr.NormalizeURL(u)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, u)
	}
	return out
}
