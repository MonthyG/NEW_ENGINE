package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"hostinginside/waf/manager/store"
)

func TestBackupDropsAccessLogKeepsTheRest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "waf.db"))
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.SetSetting(ctx, "k", "v"))
	require.NoError(t, st.InsertRequests(ctx, []store.Request{{TS: time.Now(), SiteID: "s_a"}}))
	require.NoError(t, st.InsertEvents(ctx, []store.Event{{TS: time.Now(), SiteID: "s_a", Type: "waf_match"}}))

	b := &Backups{Store: st, Dir: filepath.Join(dir, "backups")}
	f, err := b.Now(ctx)
	require.NoError(t, err)
	p, ok := b.Path(f.Name)
	require.True(t, ok)
	require.NoError(t, store.CheckFile(ctx, p))
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}

	db, err := sql.Open("sqlite", p)
	require.NoError(t, err)
	defer db.Close()
	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&n))
	assert.Zero(t, n)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n))
	assert.Equal(t, 1, n)
	var v string
	require.NoError(t, db.QueryRow(`SELECT value FROM settings WHERE key = 'k'`).Scan(&v))
	assert.Equal(t, "v", v)
}

func TestPruneKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	names := []string{"waf-20261024-030000.db", "waf-20261025-030000.db", "waf-20261026-030000.db", "waf-20261027-030000.db"}
	for _, n := range append(names, "notes.txt") {
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600))
	}
	b := &Backups{Dir: dir, Keep: 2}
	b.prune()
	list, err := b.List()
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, names[3], list[0].Name)
	assert.Equal(t, names[2], list[1].Name)
	_, err = os.Stat(filepath.Join(dir, "notes.txt"))
	assert.NoError(t, err, "files that aren't backups are left alone")
}

func TestValidName(t *testing.T) {
	assert.True(t, ValidName("waf-20261027-030000.db"))
	for _, n := range []string{"waf.db", "../waf-20261027-030000.db", "waf-20261027-030000.db.tmp", ""} {
		assert.False(t, ValidName(n), n)
	}
}
