package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Object kinds.
const (
	KindCert    = "cert"
	KindIPGroup = "ip_group"
	KindRule    = "rule"
)

// Object is a stored global object (certificate, IP group, global rule); Doc
// is its JSON document.
type Object struct {
	Kind, ID         string
	Doc              json.RawMessage
	Created, Updated time.Time
}

func listObjects(ctx context.Context, q queryer, kind string) ([]Object, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, doc, created, updated FROM objects WHERE kind = ? ORDER BY created, id`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Object
	for rows.Next() {
		o := Object{Kind: kind}
		var doc string
		var c, u int64
		if err := rows.Scan(&o.ID, &doc, &c, &u); err != nil {
			return nil, err
		}
		o.Doc = json.RawMessage(doc)
		o.Created, o.Updated = time.UnixMilli(c).UTC(), time.UnixMilli(u).UTC()
		out = append(out, o)
	}
	return out, rows.Err()
}

// ListObjects returns all objects of a kind, oldest first.
func (t *Tx) ListObjects(kind string) ([]Object, error) { return listObjects(t.ctx, t.tx, kind) }

// ListObjects returns all objects of a kind, oldest first.
func (s *Store) ListObjects(ctx context.Context, kind string) ([]Object, error) {
	return listObjects(ctx, s.db, kind)
}

// GetObject returns one object and whether it exists.
func (t *Tx) GetObject(kind, id string) (Object, bool, error) {
	o := Object{Kind: kind, ID: id}
	var doc string
	var c, u int64
	err := t.tx.QueryRowContext(t.ctx,
		`SELECT doc, created, updated FROM objects WHERE kind = ? AND id = ?`, kind, id).Scan(&doc, &c, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return Object{}, false, nil
	}
	if err != nil {
		return Object{}, false, err
	}
	o.Doc = json.RawMessage(doc)
	o.Created, o.Updated = time.UnixMilli(c).UTC(), time.UnixMilli(u).UTC()
	return o, true, nil
}

// PutObject inserts or replaces an object, marshalling doc to JSON.
func (t *Tx) PutObject(kind, id string, doc any, created, updated time.Time) error {
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(t.ctx,
		`INSERT INTO objects(kind, id, doc, created, updated) VALUES(?, ?, ?, ?, ?)
		 ON CONFLICT(kind, id) DO UPDATE SET doc = excluded.doc, updated = excluded.updated`,
		kind, id, string(b), created.UnixMilli(), updated.UnixMilli())
	return err
}

// DeleteObject removes an object and reports whether it existed.
func (t *Tx) DeleteObject(kind, id string) (bool, error) {
	res, err := t.tx.ExecContext(t.ctx, `DELETE FROM objects WHERE kind = ? AND id = ?`, kind, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
