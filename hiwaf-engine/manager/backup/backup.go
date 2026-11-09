// Package backup keeps rotating copies of the manager's database: one every
// interval, the newest Keep of them, in Dir.
package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"hostinginside/waf/manager/store"
)

// nameRE matches the backup files this package writes: waf-20261027-030000.db.
var nameRE = regexp.MustCompile(`^waf-\d{8}-\d{6}\.db$`)

// ValidName reports whether name is a backup file name (and so safe to join
// to Dir).
func ValidName(name string) bool { return nameRE.MatchString(name) }

// File is one backup on disk.
type File struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
}

// Backups makes and rotates backups. The zero Every and Keep mean 24 h and 7.
type Backups struct {
	Store  *store.Store
	Dir    string
	Every  time.Duration
	Keep   int
	Log    *slog.Logger
	Failed func(err error) // called when a scheduled backup fails; may be nil

	mu sync.Mutex // one backup at a time
}

// Now makes a backup, prunes old ones and returns the new file.
func (b *Backups) Now(ctx context.Context) (File, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := os.MkdirAll(b.Dir, 0o700); err != nil {
		return File{}, err
	}
	t := time.Now().UTC()
	name := "waf-" + t.Format("20060102-150405") + ".db"
	path := filepath.Join(b.Dir, name)
	if _, err := os.Stat(path); err == nil {
		return File{}, fmt.Errorf("backup %s already exists; try again in a second", name)
	}
	if err := b.Store.Backup(ctx, path); err != nil {
		return File{}, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return File{}, err
	}
	b.prune()
	return File{Name: name, Size: fi.Size(), Created: t}, nil
}

// List returns the backups, newest first.
func (b *Backups) List() ([]File, error) {
	ents, err := os.ReadDir(b.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return []File{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []File{}
	for _, e := range ents {
		if !ValidName(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		t, _ := time.Parse("20060102-150405", e.Name()[4:19])
		out = append(out, File{Name: e.Name(), Size: fi.Size(), Created: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Path returns the path of a backup by name, or false if there is none.
func (b *Backups) Path(name string) (string, bool) {
	if !ValidName(name) {
		return "", false
	}
	p := filepath.Join(b.Dir, name)
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, true
}

func (b *Backups) keep() int {
	if b.Keep <= 0 {
		return 7
	}
	return b.Keep
}

// prune deletes all but the newest Keep backups.
func (b *Backups) prune() {
	list, err := b.List()
	if err != nil {
		return
	}
	for _, f := range list[min(len(list), b.keep()):] {
		if err := os.Remove(filepath.Join(b.Dir, f.Name)); err != nil && b.Log != nil {
			b.Log.Warn("backup: prune", "file", f.Name, "err", err)
		}
	}
}

// Run makes a backup every interval until ctx ends. The first one is due an
// interval after the newest existing backup, so restarts don't pile them up.
func (b *Backups) Run(ctx context.Context) {
	every := b.Every
	if every <= 0 {
		every = 24 * time.Hour
	}
	wait := time.Minute // let the manager settle first
	if list, err := b.List(); err == nil && len(list) > 0 {
		wait = max(wait, time.Until(list[0].Created.Add(every)))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		f, err := b.Now(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			if b.Log != nil {
				b.Log.Error("backup failed", "err", err)
			}
			if b.Failed != nil {
				b.Failed(err)
			}
		case b.Log != nil:
			b.Log.Info("backup written", "file", f.Name, "bytes", f.Size)
		}
		wait = every
	}
}
