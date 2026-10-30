package main

// hoot -set key=value: change individual kind-0 profile fields while keeping
// the rest. (-u publishes exactly the JSON given, so any field left out was
// erased.)

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"hoot/internal/relay"

	"github.com/nbd-wtf/go-nostr"
)

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ", ") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

var profileKey = regexp.MustCompile(`^[a-z0-9_]+$`)

// parseSets turns ["name=Alice", "website="] into field updates; an empty
// value removes the field (nil).
func parseSets(items []string) (map[string]*string, error) {
	out := map[string]*string{}
	for _, it := range items {
		k, v, ok := strings.Cut(it, "=")
		k = strings.TrimSpace(k)
		if !ok || !profileKey.MatchString(k) {
			return nil, fmt.Errorf("-set %q: use key=value with a lowercase key, e.g. -set name=Alice (an empty value removes the field)", it)
		}
		if v == "" {
			out[k] = nil
		} else {
			val := v
			out[k] = &val
		}
	}
	return out, nil
}

// mergeProfile applies sets to the current kind-0 content, keeping every
// other field (including ones hoot doesn't know about) as it was. It
// returns the new content and a human-readable list of changes.
func mergeProfile(current string, sets map[string]*string) (string, []string, error) {
	fields := map[string]json.RawMessage{}
	if strings.TrimSpace(current) != "" {
		if err := json.Unmarshal([]byte(current), &fields); err != nil {
			return "", nil, fmt.Errorf("your current profile isn't valid JSON (%v); use -u to replace it", err)
		}
	}
	keys := make([]string, 0, len(sets))
	for k := range sets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var changes []string
	for _, k := range keys {
		v := sets[k]
		old, had := fields[k]
		if v == nil {
			if had {
				delete(fields, k)
				changes = append(changes, fmt.Sprintf("- %s (was %s)", k, old))
			}
			continue
		}
		b, _ := json.Marshal(*v)
		if had && string(old) == string(b) {
			continue
		}
		fields[k] = b
		if had {
			changes = append(changes, fmt.Sprintf("~ %s: %s → %s", k, old, b))
		} else {
			changes = append(changes, fmt.Sprintf("+ %s: %s", k, b))
		}
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return "", nil, err
	}
	return string(out), changes, nil
}

// setProfileFields fetches the newest profile, applies sets and publishes
// the result.
func setProfileFields(sk, pk string, relays []string, sets map[string]*string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	events, _ := relay.QueryAll(ctx, relays, nostr.Filter{Kinds: []int{0}, Authors: []string{pk}, Limit: 1})
	current := ""
	if len(events) > 0 {
		current = events[0].Content
	} else {
		fmt.Println("No existing profile found on your relays; creating a new one.")
	}

	content, changes, err := mergeProfile(current, sets)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		fmt.Println("Nothing to change.")
		return nil
	}
	fmt.Println("Profile changes:")
	for _, c := range changes {
		fmt.Println("  " + c)
	}
	ev := nostr.Event{Kind: 0, Content: content, CreatedAt: nostr.Now(), Tags: nostr.Tags{}}
	if len(events) > 0 && ev.CreatedAt <= events[0].CreatedAt {
		ev.CreatedAt = events[0].CreatedAt + 1 // replaceable: must be newer
	}
	if err := ev.Sign(sk); err != nil {
		return err
	}
	return publishAndReport(relays, ev, "profile update")
}
