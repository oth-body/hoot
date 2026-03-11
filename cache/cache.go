package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/nbd-wtf/go-nostr"
	_ "modernc.org/sqlite"
)

// Cache provides persistent storage for Nostr events and metadata
type Cache struct {
	db      *sql.DB
	dbPath  string
	cleanup context.CancelFunc
}

// Event represents a cached Nostr event with metadata
type Event struct {
	ID        string
	PubKey    string
	CreatedAt int64
	Kind      int
	Content   string
	Sig       string
	Tags      []byte
	CachedAt  time.Time
	ExpiresAt *time.Time
}

// Profile represents cached profile metadata
type Profile struct {
	PubKey    string
	Name      string
	About     string
	Picture   string
	NIP05     string
	UpdatedAt int64
	CachedAt  time.Time
	ExpiresAt *time.Time
}

// RelayStats tracks relay performance metrics
type RelayStats struct {
	URL                string
	AvgResponseTime    int64
	SuccessRate        float64
	LastCheck          time.Time
	IsActive           bool
	TotalRequests      int64
	SuccessfulRequests int64
}

// New creates a new Cache instance
func New(dataDir string) (*Cache, error) {
	dbPath := filepath.Join(dataDir, "hoot_cache.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache database: %w", err)
	}

	// Enable foreign keys and WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	cache := &Cache{
		db:     db,
		dbPath: dbPath,
	}

	if err := cache.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create cache tables: %w", err)
	}

	return cache, nil
}

// Close closes the cache database
func (c *Cache) Close() error {
	if c.cleanup != nil {
		c.cleanup()
	}
	return c.db.Close()
}

// createTables creates the necessary database tables
func (c *Cache) createTables() error {
	schema := `
		CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			pubkey TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			kind INTEGER NOT NULL,
			content TEXT,
			sig TEXT NOT NULL,
			tags BLOB,
			cached_at INTEGER NOT NULL,
			expires_at INTEGER
		);

		CREATE INDEX IF NOT EXISTS idx_events_pubkey ON events(pubkey);
		CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
		CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
		CREATE INDEX IF NOT EXISTS idx_events_expires_at ON events(expires_at);

		CREATE TABLE IF NOT EXISTS profiles (
			pubkey TEXT PRIMARY KEY,
			name TEXT,
			about TEXT,
			picture TEXT,
			nip05 TEXT,
			updated_at INTEGER NOT NULL,
			cached_at INTEGER NOT NULL,
			expires_at INTEGER
		);

		CREATE INDEX IF NOT EXISTS idx_profiles_expires_at ON profiles(expires_at);

		CREATE TABLE IF NOT EXISTS relay_stats (
			url TEXT PRIMARY KEY,
			avg_response_time INTEGER DEFAULT 0,
			success_rate REAL DEFAULT 0.0,
			last_check INTEGER NOT NULL,
			is_active INTEGER DEFAULT 1,
			total_requests INTEGER DEFAULT 0,
			successful_requests INTEGER DEFAULT 0
		);
	`

	_, err := c.db.Exec(schema)
	return err
}

// StoreEvent stores an event in the cache
func (c *Cache) StoreEvent(event *nostr.Event, ttl time.Duration) error {
	tags, err := json.Marshal(event.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	cachedAt := time.Now()
	var expiresAt *int64
	if ttl > 0 {
		exp := cachedAt.Add(ttl).Unix()
		expiresAt = &exp
	}

	_, err = c.db.Exec(`
		INSERT OR REPLACE INTO events 
		(id, pubkey, created_at, kind, content, sig, tags, cached_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.PubKey, int64(event.CreatedAt), event.Kind,
		event.Content, event.Sig, tags, cachedAt.Unix(), expiresAt,
	)

	return err
}

// GetEvent retrieves an event from the cache
func (c *Cache) GetEvent(id string) (*nostr.Event, error) {
	row := c.db.QueryRow(`
		SELECT id, pubkey, created_at, kind, content, sig, tags
		FROM events
		WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)`,
		id, time.Now().Unix())

	var event nostr.Event
	var tags []byte
	var createdAt int64
	err := row.Scan(&event.ID, &event.PubKey, &createdAt,
		&event.Kind, &event.Content, &event.Sig, &tags)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	event.CreatedAt = nostr.Timestamp(createdAt)

	if err := json.Unmarshal(tags, &event.Tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	return &event, nil
}

// GetEventsByPubKey retrieves events for a specific public key
func (c *Cache) GetEventsByPubKey(pubkey string, kind int, limit int) ([]*nostr.Event, error) {
	query := `
		SELECT id, pubkey, created_at, kind, content, sig, tags
		FROM events
		WHERE (expires_at IS NULL OR expires_at > ?)`

	args := []interface{}{time.Now().Unix()}

	if pubkey != "" {
		query += " AND pubkey = ?"
		args = append(args, pubkey)
	}

	if kind >= 0 {
		query += " AND kind = ?"
		args = append(args, kind)
	}

	query += " ORDER BY created_at DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*nostr.Event
	for rows.Next() {
		var event nostr.Event
		var tags []byte
		var createdAt int64
		err := rows.Scan(&event.ID, &event.PubKey, &createdAt,
			&event.Kind, &event.Content, &event.Sig, &tags)
		if err != nil {
			return nil, err
		}
		event.CreatedAt = nostr.Timestamp(createdAt)
		if err := json.Unmarshal(tags, &event.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}
		events = append(events, &event)
	}

	return events, rows.Err()
}

// StoreProfile stores profile metadata in the cache
func (c *Cache) StoreProfile(pubkey string, name, about, picture, nip05 string, updatedAt int64, ttl time.Duration) error {
	cachedAt := time.Now()
	var expiresAt *int64
	if ttl > 0 {
		exp := cachedAt.Add(ttl).Unix()
		expiresAt = &exp
	}

	_, err := c.db.Exec(`
		INSERT OR REPLACE INTO profiles
		(pubkey, name, about, picture, nip05, updated_at, cached_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		pubkey, name, about, picture, nip05, updatedAt, cachedAt.Unix(), expiresAt,
	)

	return err
}

// GetProfile retrieves a profile from the cache
func (c *Cache) GetProfile(pubkey string) (*Profile, error) {
	row := c.db.QueryRow(`
		SELECT pubkey, name, about, picture, nip05, updated_at, cached_at, expires_at
		FROM profiles
		WHERE pubkey = ? AND (expires_at IS NULL OR expires_at > ?)`,
		pubkey, time.Now().Unix())

	var p Profile
	var cachedAt int64
	var expiresAt sql.NullInt64
	err := row.Scan(&p.PubKey, &p.Name, &p.About, &p.Picture, &p.NIP05,
		&p.UpdatedAt, &cachedAt, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	p.CachedAt = time.Unix(cachedAt, 0)

	if expiresAt.Valid {
		expTime := time.Unix(expiresAt.Int64, 0)
		p.ExpiresAt = &expTime
	}

	return &p, nil
}

// UpdateRelayStats updates relay performance statistics
func (c *Cache) UpdateRelayStats(url string, responseTime int64, success bool) error {
	_, err := c.db.Exec(`
		INSERT INTO relay_stats (url, avg_response_time, success_rate, last_check, is_active, total_requests, successful_requests)
		VALUES (?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT(url) DO UPDATE SET
			avg_response_time = (relay_stats.avg_response_time * relay_stats.total_requests + excluded.avg_response_time) / (relay_stats.total_requests + 1),
			success_rate = (relay_stats.success_rate * relay_stats.total_requests + excluded.success_rate) / (relay_stats.total_requests + 1),
			last_check = excluded.last_check,
			is_active = excluded.is_active,
			total_requests = relay_stats.total_requests + 1,
			successful_requests = relay_stats.successful_requests + excluded.successful_requests`,
		url, responseTime, map[bool]float64{true: 1.0, false: 0.0}[success],
		time.Now().Unix(), success, map[bool]int64{true: 1, false: 0}[success],
	)
	return err
}

// GetRelayStats retrieves statistics for a specific relay
func (c *Cache) GetRelayStats(url string) (*RelayStats, error) {
	row := c.db.QueryRow(`
		SELECT url, avg_response_time, success_rate, last_check, is_active, total_requests, successful_requests
		FROM relay_stats
		WHERE url = ?`, url)

	var rs RelayStats
	var isActive int
	var lastCheck int64
	err := row.Scan(&rs.URL, &rs.AvgResponseTime, &rs.SuccessRate,
		&lastCheck, &isActive, &rs.TotalRequests, &rs.SuccessfulRequests)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	rs.LastCheck = time.Unix(lastCheck, 0)
	rs.IsActive = isActive == 1
	return &rs, nil
}

// GetActiveRelays retrieves all relays sorted by performance
func (c *Cache) GetActiveRelays() ([]*RelayStats, error) {
	rows, err := c.db.Query(`
		SELECT url, avg_response_time, success_rate, last_check, is_active, total_requests, successful_requests
		FROM relay_stats
		WHERE is_active = 1
		ORDER BY success_rate DESC, avg_response_time ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var relays []*RelayStats
	for rows.Next() {
		var rs RelayStats
		var isActive int
		var lastCheck int64
		err := rows.Scan(&rs.URL, &rs.AvgResponseTime, &rs.SuccessRate,
			&lastCheck, &isActive, &rs.TotalRequests, &rs.SuccessfulRequests)
		if err != nil {
			return nil, err
		}
		rs.LastCheck = time.Unix(lastCheck, 0)
		rs.IsActive = isActive == 1
		relays = append(relays, &rs)
	}

	return relays, rows.Err()
}

// CleanupExpired removes expired entries from the cache
func (c *Cache) CleanupExpired() error {
	now := time.Now().Unix()

	_, err := c.db.Exec("DELETE FROM events WHERE expires_at IS NOT NULL AND expires_at <= ?", now)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired events: %w", err)
	}

	_, err = c.db.Exec("DELETE FROM profiles WHERE expires_at IS NOT NULL AND expires_at <= ?", now)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired profiles: %w", err)
	}

	return nil
}

// Clear clears all cached data
func (c *Cache) Clear() error {
	_, err := c.db.Exec("DELETE FROM events")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("DELETE FROM profiles")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("DELETE FROM relay_stats")
	return err
}

// StartCleanup starts the periodic cleanup of expired cache entries
func (c *Cache) StartCleanup(interval time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	c.cleanup = cancel

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := c.CleanupExpired(); err != nil {
					// Log error but don't stop the cleanup routine
					fmt.Printf("Cache cleanup error: %v\n", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stats returns cache statistics
func (c *Cache) Stats() (events, profiles, relays int64, err error) {
	err = c.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&events)
	if err != nil {
		return 0, 0, 0, err
	}

	err = c.db.QueryRow("SELECT COUNT(*) FROM profiles").Scan(&profiles)
	if err != nil {
		return 0, 0, 0, err
	}

	err = c.db.QueryRow("SELECT COUNT(*) FROM relay_stats").Scan(&relays)
	if err != nil {
		return 0, 0, 0, err
	}

	return events, profiles, relays, nil
}
