package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A database from before projects keeps its tokens: they become operator
// tokens, and new tokens can carry a project.
func TestTokensGainProjectColumn(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE tokens (id TEXT PRIMARY KEY, name TEXT NOT NULL, hash TEXT NOT NULL UNIQUE,
		created INTEGER NOT NULL, last_used INTEGER NOT NULL DEFAULT 0);
		INSERT INTO tokens(id, name, hash, created) VALUES('t_old', 'old', 'h-old', 1)`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	st, err := Open(path)
	require.NoError(t, err)
	defer st.Close()
	old, ok, err := st.TokenByHash(ctx, "h-old")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "", old.Project)

	require.NoError(t, st.CreateToken(ctx, "t_new", "alpha svc", "alpha", "h-new", time.Time{}))
	got, ok, err := st.TokenByHash(ctx, "h-new")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, Token{ID: "t_new", Name: "alpha svc", Project: "alpha"}, Token{ID: got.ID, Name: got.Name, Project: got.Project})
	list, err := st.ListTokens(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestExpiredTokenStopsWorking(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.CreateToken(ctx, "t_live", "live", "", "h-live", time.Now().Add(time.Hour)))
	require.NoError(t, st.CreateToken(ctx, "t_dead", "dead", "", "h-dead", time.Now().Add(-time.Second)))
	_, ok, err := st.TokenByHash(ctx, "h-live")
	require.NoError(t, err)
	assert.True(t, ok)
	_, ok, err = st.TokenByHash(ctx, "h-dead")
	require.NoError(t, err)
	assert.False(t, ok)
	list, err := st.ListTokens(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2) // still listed, so the operator sees it and can delete it
	for _, tk := range list {
		assert.False(t, tk.Expires.IsZero())
	}
}
