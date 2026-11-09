package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// User is a console account.
type User struct {
	Username    string
	Hash        string // bcrypt
	TOTPSecret  string // base32, set while enabling or once enabled
	TOTPEnabled bool
	Created     time.Time
}

// ErrNoUser is returned when a user doesn't exist.
var ErrNoUser = errors.New("no such user")

// CountUsers returns the number of console users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// GetUser returns a user or ErrNoUser.
func (s *Store) GetUser(ctx context.Context, name string) (User, error) {
	u := User{Username: name}
	var enabled int
	var created int64
	err := s.db.QueryRowContext(ctx,
		`SELECT hash, totp_secret, totp_enabled, created FROM users WHERE username = ?`, name).
		Scan(&u.Hash, &u.TOTPSecret, &enabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNoUser
	}
	if err != nil {
		return User{}, err
	}
	u.TOTPEnabled, u.Created = enabled == 1, time.UnixMilli(created).UTC()
	return u, nil
}

// PutUser inserts or replaces a user.
func (s *Store) PutUser(ctx context.Context, u User) error {
	enabled := 0
	if u.TOTPEnabled {
		enabled = 1
	}
	if u.Created.IsZero() {
		u.Created = time.Now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users(username, hash, totp_secret, totp_enabled, created) VALUES(?, ?, ?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET hash = excluded.hash, totp_secret = excluded.totp_secret,
		 totp_enabled = excluded.totp_enabled`,
		u.Username, u.Hash, u.TOTPSecret, enabled, u.Created.UnixMilli())
	return err
}

// CreateSession stores a session by the hash of its token.
func (s *Store) CreateSession(ctx context.Context, idHash, user string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(id, username, expires, created) VALUES(?, ?, ?, ?)`,
		idHash, user, expires.UnixMilli(), time.Now().UnixMilli())
	return err
}

// SessionUser returns the user of an unexpired session.
func (s *Store) SessionUser(ctx context.Context, idHash string, now time.Time) (string, bool, error) {
	var user string
	err := s.db.QueryRowContext(ctx,
		`SELECT username FROM sessions WHERE id = ? AND expires > ?`, idHash, now.UnixMilli()).Scan(&user)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return user, err == nil, err
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, idHash)
	return err
}

// DeleteUserSessions removes every session of a user except keep (a hash; may be "").
func (s *Store) DeleteUserSessions(ctx context.Context, user, keep string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE username = ? AND id <> ?`, user, keep)
	return err
}

// Token is an API token; the secret itself is never stored. A token with a
// Project acts only for that project.
type Token struct {
	ID, Name, Project          string
	Created, LastUsed, Expires time.Time // Expires zero = never
}

// CreateToken stores a token by the hash of its secret. A zero expires never expires.
func (s *Store) CreateToken(ctx context.Context, id, name, project, hash string, expires time.Time) error {
	var exp int64
	if !expires.IsZero() {
		exp = expires.UnixMilli()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO tokens(id, name, project, hash, created, expires) VALUES(?, ?, ?, ?, ?, ?)`,
		id, name, project, hash, time.Now().UnixMilli(), exp)
	return err
}

// TokenByHash returns the unexpired token with the given hash and records its use.
func (s *Store) TokenByHash(ctx context.Context, hash string) (Token, bool, error) {
	var t Token
	err := s.db.QueryRowContext(ctx, `SELECT id, name, project FROM tokens WHERE hash = ? AND (expires = 0 OR expires > ?)`,
		hash, time.Now().UnixMilli()).Scan(&t.ID, &t.Name, &t.Project)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, false, nil
	}
	if err != nil {
		return Token{}, false, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE tokens SET last_used = ? WHERE id = ?`, time.Now().UnixMilli(), t.ID)
	return t, true, err
}

// ListTokens returns all tokens, newest first.
func (s *Store) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, project, created, last_used, expires FROM tokens ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		var c, l, e int64
		if err := rows.Scan(&t.ID, &t.Name, &t.Project, &c, &l, &e); err != nil {
			return nil, err
		}
		t.Created = time.UnixMilli(c).UTC()
		if e > 0 {
			t.Expires = time.UnixMilli(e).UTC()
		}
		if l > 0 {
			t.LastUsed = time.UnixMilli(l).UTC()
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteToken removes a token and reports whether it existed.
func (s *Store) DeleteToken(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Purge deletes requests older than reqBefore, events older than evBefore and
// expired sessions.
func (s *Store) Purge(ctx context.Context, reqBefore, evBefore, now time.Time) error {
	for _, q := range []struct {
		sql string
		arg int64
	}{
		{`DELETE FROM requests WHERE ts < ?`, reqBefore.UnixMilli()},
		{`DELETE FROM events WHERE ts < ?`, evBefore.UnixMilli()},
		{`DELETE FROM sessions WHERE expires <= ?`, now.UnixMilli()},
	} {
		if _, err := s.db.ExecContext(ctx, q.sql, q.arg); err != nil {
			return err
		}
	}
	return nil
}
