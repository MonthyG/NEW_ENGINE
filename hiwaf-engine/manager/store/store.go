// Package store persists sites, certificates, settings and security events in
// SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"hostinginside/waf/manager/site"
)

const schema = `
CREATE TABLE IF NOT EXISTS sites (
	id      TEXT PRIMARY KEY,
	doc     TEXT NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS certs (
	site_id  TEXT PRIMARY KEY,
	cert_pem TEXT NOT NULL,
	key_pem  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        INTEGER NOT NULL,
	site_id   TEXT NOT NULL,
	type      TEXT NOT NULL,
	client_ip TEXT NOT NULL,
	host      TEXT NOT NULL,
	method    TEXT NOT NULL,
	uri       TEXT NOT NULL,
	rule_id   TEXT NOT NULL,
	msg       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_site_ts ON events(site_id, ts);
CREATE TABLE IF NOT EXISTS requests (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        INTEGER NOT NULL,
	site_id   TEXT NOT NULL,
	client_ip TEXT NOT NULL,
	country   TEXT NOT NULL,
	method    TEXT NOT NULL,
	host      TEXT NOT NULL,
	uri       TEXT NOT NULL,
	status    INTEGER NOT NULL,
	bytes     INTEGER NOT NULL,
	dur_ms    REAL NOT NULL,
	ua        TEXT NOT NULL,
	referer   TEXT NOT NULL,
	html      INTEGER NOT NULL,
	action    TEXT NOT NULL,
	kind      TEXT NOT NULL,
	tx_id     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS requests_site_ts ON requests(site_id, ts);
CREATE INDEX IF NOT EXISTS requests_tx ON requests(tx_id) WHERE tx_id <> '';
CREATE TABLE IF NOT EXISTS objects (
	kind    TEXT NOT NULL,
	id      TEXT NOT NULL,
	doc     TEXT NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL,
	PRIMARY KEY (kind, id)
);
CREATE TABLE IF NOT EXISTS users (
	username     TEXT PRIMARY KEY,
	hash         TEXT NOT NULL,
	totp_secret  TEXT NOT NULL DEFAULT '',
	totp_enabled INTEGER NOT NULL DEFAULT 0,
	created      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	id       TEXT PRIMARY KEY,
	username TEXT NOT NULL,
	expires  INTEGER NOT NULL,
	created  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
	id        TEXT PRIMARY KEY,
	name      TEXT NOT NULL,
	hash      TEXT NOT NULL UNIQUE,
	created   INTEGER NOT NULL,
	last_used INTEGER NOT NULL DEFAULT 0
);
`

// eventColumns are columns added to events after the first release; Open
// adds any that are missing.
var eventColumns = []struct{ name, def string }{
	{"tx_id", "TEXT NOT NULL DEFAULT ''"},
	{"data", "TEXT NOT NULL DEFAULT ''"},
	{"severity", "INTEGER NOT NULL DEFAULT 9"},
	{"category", "TEXT NOT NULL DEFAULT ''"},
	{"country", "TEXT NOT NULL DEFAULT ''"},
}

// tokenColumns are columns added to tokens after the first release.
var tokenColumns = []struct{ name, def string }{
	{"project", "TEXT NOT NULL DEFAULT ''"},
	{"expires", "INTEGER NOT NULL DEFAULT 0"}, // unix ms; 0 = never
}

// addColumns adds the columns of table that are missing.
func addColumns(db *sql.DB, table string, cols []struct{ name, def string }) error {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	for _, c := range cols {
		if !have[c.name] {
			if _, err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + c.name + ` ` + c.def); err != nil {
				return err
			}
		}
	}
	return nil
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	if err := addColumns(db, "events", eventColumns); err != nil {
		return err
	}
	if err := addColumns(db, "tokens", tokenColumns); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS events_tx ON events(tx_id) WHERE tx_id <> '';
		CREATE INDEX IF NOT EXISTS events_type_ts ON events(type, ts)`)
	return err
}

// Store is a SQLite-backed store. It uses a single connection, which
// serialises all access and sidesteps SQLITE_BUSY between our own writers.
// Consequently a Tx callback must use only its *Tx, never the Store.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the database at path and migrates it.
func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SiteRecord is a stored site.
type SiteRecord struct {
	ID               string
	Doc              site.Doc
	Created, Updated time.Time
}

// Tx is a transaction handle, valid only inside the Store.Tx callback.
type Tx struct {
	tx  *sql.Tx
	ctx context.Context
}

// Tx runs fn in a transaction, committing only when fn returns nil. It rolls
// back on error or panic (re-panicking).
func (s *Store) Tx(ctx context.Context, fn func(*Tx) error) error {
	sqlTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = sqlTx.Rollback()
			panic(p)
		}
	}()
	if err := fn(&Tx{tx: sqlTx, ctx: ctx}); err != nil {
		_ = sqlTx.Rollback()
		return err
	}
	if err := sqlTx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func listSites(ctx context.Context, q queryer) ([]SiteRecord, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, doc, created, updated FROM sites ORDER BY created, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SiteRecord
	for rows.Next() {
		rec, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func scanSite(sc interface{ Scan(...any) error }) (SiteRecord, error) {
	var rec SiteRecord
	var doc string
	var created, updated int64
	if err := sc.Scan(&rec.ID, &doc, &created, &updated); err != nil {
		return SiteRecord{}, err
	}
	if err := json.Unmarshal([]byte(doc), &rec.Doc); err != nil {
		return SiteRecord{}, fmt.Errorf("store: site %s: bad doc: %w", rec.ID, err)
	}
	rec.Created = time.UnixMilli(created).UTC()
	rec.Updated = time.UnixMilli(updated).UTC()
	return rec, nil
}

func certs(ctx context.Context, q queryer) (map[string]site.Cert, error) {
	rows, err := q.QueryContext(ctx, `SELECT site_id, cert_pem, key_pem FROM certs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]site.Cert{}
	for rows.Next() {
		var id string
		var c site.Cert
		if err := rows.Scan(&id, &c.CertPEM, &c.KeyPEM); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, rows.Err()
}

// ListSites returns all sites ordered by creation time.
func (t *Tx) ListSites() ([]SiteRecord, error) { return listSites(t.ctx, t.tx) }

// GetSite returns one site and whether it exists.
func (t *Tx) GetSite(id string) (SiteRecord, bool, error) {
	rec, err := scanSite(t.tx.QueryRowContext(t.ctx,
		`SELECT id, doc, created, updated FROM sites WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SiteRecord{}, false, nil
	}
	if err != nil {
		return SiteRecord{}, false, err
	}
	return rec, true, nil
}

// PutSite inserts or replaces a site.
func (t *Tx) PutSite(r SiteRecord) error {
	doc, err := json.Marshal(r.Doc)
	if err != nil {
		return fmt.Errorf("store: marshal doc: %w", err)
	}
	_, err = t.tx.ExecContext(t.ctx,
		`INSERT INTO sites(id, doc, created, updated) VALUES(?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET doc = excluded.doc, created = excluded.created, updated = excluded.updated`,
		r.ID, string(doc), r.Created.UnixMilli(), r.Updated.UnixMilli())
	return err
}

// DeleteSite removes a site and its certificate; it reports whether the site existed.
func (t *Tx) DeleteSite(id string) (bool, error) {
	res, err := t.tx.ExecContext(t.ctx, `DELETE FROM sites WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if _, err := t.tx.ExecContext(t.ctx, `DELETE FROM certs WHERE site_id = ?`, id); err != nil {
		return false, err
	}
	return n > 0, nil
}

// PutCert stores or replaces a site's certificate.
func (t *Tx) PutCert(siteID string, c site.Cert) error {
	_, err := t.tx.ExecContext(t.ctx,
		`INSERT INTO certs(site_id, cert_pem, key_pem) VALUES(?, ?, ?)
		 ON CONFLICT(site_id) DO UPDATE SET cert_pem = excluded.cert_pem, key_pem = excluded.key_pem`,
		siteID, c.CertPEM, c.KeyPEM)
	return err
}

// Certs returns all certificates keyed by site ID.
func (t *Tx) Certs() (map[string]site.Cert, error) { return certs(t.ctx, t.tx) }

// ListSites returns all sites ordered by creation time.
func (s *Store) ListSites(ctx context.Context) ([]SiteRecord, error) {
	return listSites(ctx, s.db)
}

// Certs returns all certificates keyed by site ID.
func (s *Store) Certs(ctx context.Context) (map[string]site.Cert, error) {
	return certs(ctx, s.db)
}

// Setting returns a setting value and whether it exists.
func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	return setting(ctx, s.db, key)
}

// SetSetting stores a setting.
func (s *Store) SetSetting(ctx context.Context, key, val string) error {
	return setSetting(ctx, s.db, key, val)
}

// Setting returns a setting value and whether it exists.
func (t *Tx) Setting(key string) (string, bool, error) { return setting(t.ctx, t.tx, key) }

// SetSetting stores a setting.
func (t *Tx) SetSetting(key, val string) error { return setSetting(t.ctx, t.tx, key, val) }

type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func setting(ctx context.Context, q rowQueryer, key string) (string, bool, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func setSetting(ctx context.Context, q rowQueryer, key, val string) error {
	_, err := q.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, val)
	return err
}

// Event is a security event. Severity is the syslog level Coraza reports
// (2 critical ... 5 notice), 9 when unknown; Category is the protection key
// of a WAF rule, "score" for CRS scoring rules.
type Event struct {
	ID                                                     int64
	TS                                                     time.Time
	SiteID, Type, ClientIP, Host, Method, URI, RuleID, Msg string
	TxID, Data, Category, Country                          string
	Severity                                               int
}

// InsertEvents stores events in one transaction.
func (s *Store) InsertEvents(ctx context.Context, evs []Event) error {
	if len(evs) == 0 {
		return nil
	}
	return s.Tx(ctx, func(t *Tx) error {
		stmt, err := t.tx.PrepareContext(ctx,
			`INSERT INTO events(ts, site_id, type, client_ip, host, method, uri, rule_id, msg,
			 tx_id, data, severity, category, country)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range evs {
			sev := e.Severity
			if sev == 0 {
				sev = 9
			}
			if _, err := stmt.ExecContext(ctx, e.TS.UnixMilli(), e.SiteID, e.Type,
				e.ClientIP, e.Host, e.Method, e.URI, e.RuleID, e.Msg,
				e.TxID, e.Data, sev, e.Category, e.Country); err != nil {
				return err
			}
		}
		return nil
	})
}

// EventFilter narrows QueryEvents. Empty fields match everything; Limit <= 0
// means 100 and is capped at 1000.
type EventFilter struct {
	SiteID, Type, IP string
	Types            []string // any of these types; combined with Type
	TxID             string
	Since, Until     time.Time
	Limit, Offset    int
}

// where builds a WHERE clause from fixed fragments; values are always bound.
func where(siteID, typ, ip string, since time.Time) (string, []any) {
	return EventFilter{SiteID: siteID, Type: typ, IP: ip, Since: since}.where()
}

func (f EventFilter) where() (string, []any) {
	clause, args := " WHERE 1=1", []any{}
	if f.SiteID != "" {
		clause += " AND site_id = ?"
		args = append(args, f.SiteID)
	}
	if f.Type != "" {
		clause += " AND type = ?"
		args = append(args, f.Type)
	}
	if len(f.Types) > 0 {
		clause += " AND type IN (" + strings.TrimSuffix(strings.Repeat("?,", len(f.Types)), ",") + ")"
		for _, t := range f.Types {
			args = append(args, t)
		}
	}
	if f.TxID != "" {
		clause += " AND tx_id = ?"
		args = append(args, f.TxID)
	}
	if !f.Until.IsZero() {
		clause += " AND ts < ?"
		args = append(args, f.Until.UnixMilli())
	}
	ip, since := f.IP, f.Since
	if ip != "" {
		clause += " AND client_ip = ?"
		args = append(args, ip)
	}
	if !since.IsZero() {
		clause += " AND ts >= ?"
		args = append(args, since.UnixMilli())
	}
	return clause, args
}

// QueryEvents returns matching events, newest first.
func (s *Store) QueryEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	clause, args := f.where()
	args = append(args, limit, max(f.Offset, 0))
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, site_id, type, client_ip, host, method, uri, rule_id, msg,
		 tx_id, data, severity, category, country FROM events`+
			clause+` ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.SiteID, &e.Type, &e.ClientIP, &e.Host,
			&e.Method, &e.URI, &e.RuleID, &e.Msg, &e.TxID, &e.Data, &e.Severity, &e.Category, &e.Country); err != nil {
			return nil, err
		}
		e.TS = time.UnixMilli(ts).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// Count is a key with its occurrence count and, where known, how many of
// those were blocked.
type Count struct {
	Key     string
	N       int
	Blocked int
}

// Stats summarises events.
type Stats struct {
	ByType           map[string]int
	TopIPs, TopRules []Count
}

// Stats aggregates events since the given time (zero = all) for one site, or
// all sites when siteID is empty. Top lists hold up to 10 entries.
func (s *Store) Stats(ctx context.Context, siteID string, since time.Time) (Stats, error) {
	st := Stats{ByType: map[string]int{}}
	clause, args := where(siteID, "", "", since)

	rows, err := s.db.QueryContext(ctx,
		`SELECT type, COUNT(*) FROM events`+clause+` GROUP BY type`, args...)
	if err != nil {
		return Stats{}, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return Stats{}, err
		}
		st.ByType[k] = n
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Stats{}, err
	}

	// Rows must be closed before the next query: there is only one connection.
	st.TopIPs, err = s.top(ctx, "client_ip", clause+" AND client_ip <> ''", args)
	if err != nil {
		return Stats{}, err
	}
	st.TopRules, err = s.top(ctx, "rule_id", clause+" AND type = 'waf_match' AND rule_id <> ''", args)
	if err != nil {
		return Stats{}, err
	}
	return st, nil
}

// top counts the given column (a fixed internal name) under a prepared clause.
func (s *Store) top(ctx context.Context, col, clause string, args []any) ([]Count, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+col+`, COUNT(*) AS n FROM events`+clause+
			` GROUP BY `+col+` ORDER BY n DESC, `+col+` ASC LIMIT 10`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
