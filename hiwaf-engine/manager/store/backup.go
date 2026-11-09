package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
)

// Backup writes a consistent copy of the database to dest, without the access
// log (requests): it is bulky, only feeds the traffic charts and refills from
// new traffic. It reads through a connection of its own, so ingest and the API
// keep working meanwhile (WAL mode). The copy holds secrets (password hashes,
// TOTP seeds, certificate keys), so it is written 0600.
func (s *Store) Backup(ctx context.Context, dest string) error {
	tmp := dest + ".tmp"
	_ = os.Remove(tmp)
	src, err := sql.Open("sqlite", s.path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	_, err = src.ExecContext(ctx, `VACUUM INTO ?`, tmp)
	src.Close()
	if err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	if err := slim(ctx, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// slim drops the access log from a backup copy and checks the result.
func slim(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `DELETE FROM requests`); err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	return Check(ctx, db)
}

// Check runs SQLite's quick integrity check on db.
func Check(ctx context.Context, db *sql.DB) error {
	var res string
	if err := db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&res); err != nil {
		return fmt.Errorf("store: check: %w", err)
	}
	if res != "ok" {
		return fmt.Errorf("store: check: %s", res)
	}
	return nil
}

// CheckFile opens the database file at path and runs Check on it.
func CheckFile(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	return Check(ctx, db)
}
