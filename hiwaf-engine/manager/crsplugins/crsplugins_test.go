package crsplugins

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEveryProfileShipsItsFiles(t *testing.T) {
	for _, a := range Catalog {
		s := Files(a.Key)
		assert.Len(t, s.Config, 1, a.Key)
		assert.Len(t, s.Before, 1, a.Key)
		assert.NotEmpty(t, a.Paths, a.Key)
		_, err := files.ReadFile("files/" + a.Key + "/LICENSE")
		assert.NoError(t, err, a.Key+" keeps its licence")
	}
	assert.Equal(t, []string{"phpmyadmin-rule-exclusions-after.conf"}, Files("phpmyadmin").After)
	assert.False(t, Known("joomla"))
}

func TestInstallReplacesStaleFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "wordpress"), 0o755))
	stale := filepath.Join(dir, "wordpress", "wordpress-rule-exclusions-old.conf")
	require.NoError(t, os.WriteFile(stale, []byte("SecRuleEngine Off\n"), 0o644))
	require.NoError(t, Install(dir))
	assert.NoFileExists(t, stale)
	b, err := os.ReadFile(filepath.Join(dir, "wordpress", "wordpress-rule-exclusions-before.conf"))
	require.NoError(t, err)
	assert.Contains(t, string(b), "id:9507100")
	require.NoError(t, Install(dir), "running again is fine")
}
