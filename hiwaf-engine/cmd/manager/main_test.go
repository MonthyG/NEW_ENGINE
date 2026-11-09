package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manager.json")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func TestLoopback(t *testing.T) {
	for listen, want := range map[string]bool{
		"127.0.0.1:9000": true,
		"[::1]:9000":     true,
		"localhost:9000": true,
		"127.0.0.2:9000": true,
		":9000":          false,
		"0.0.0.0:9000":   false,
		"[::]:9000":      false,
		"10.0.0.1:9000":  false,
		"example.com:80": false,
		"9000":           false,
	} {
		assert.Equal(t, want, loopback(listen), listen)
	}
}

func TestDevKeyRefusedOffLoopback(t *testing.T) {
	_, err := loadConfig(writeConfig(t, `{"listen":"0.0.0.0:9000","api_keys":["change-me-dev-key"]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "change-me-dev-key")

	// The default listen address (":9000") is every interface, too.
	_, err = loadConfig(writeConfig(t, `{"api_keys":["real-key","change-me-dev-key"]}`))
	require.Error(t, err)
}

func TestDevKeyAllowedOnLoopback(t *testing.T) {
	c, err := loadConfig(writeConfig(t, `{"listen":"127.0.0.1:9000","api_keys":["change-me-dev-key"]}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"change-me-dev-key"}, c.APIKeys)

	_, err = loadConfig(writeConfig(t, `{"listen":":9000","api_keys":["a-real-key"]}`))
	require.NoError(t, err)
}

func TestExampleConfigLoads(t *testing.T) {
	_, err := loadConfig(filepath.Join("..", "..", "examples", "manager.json"))
	require.NoError(t, err)
}

func TestAdminAddress(t *testing.T) {
	for _, c := range []struct{ in, listen, bootstrap string }{
		{"unix:///data/caddy-admin.sock", "unix//data/caddy-admin.sock|0600", "http://localhost:2019"},
		{"http://localhost:2019", "localhost:2019", ""},
	} {
		l, b, err := adminAddress(c.in)
		if err != nil || l != c.listen || b != c.bootstrap {
			t.Errorf("adminAddress(%q) = %q, %q, %v; want %q, %q", c.in, l, b, err, c.listen, c.bootstrap)
		}
	}
	for _, bad := range []string{"unix://relative.sock", "localhost:2019", "https://", ""} {
		if _, _, err := adminAddress(bad); err == nil {
			t.Errorf("adminAddress(%q) accepted", bad)
		}
	}
}

func TestEnginesConfig(t *testing.T) {
	ok := `{"listen":"127.0.0.1:9000","event_log_net":"unix//data/events.sock",
		"engines":[{"name":"hk1-cmpt4","admin":"unix:///run/hiwaf/hk1-cmpt4.sock","event_listen":"127.0.0.1:7101"}]}`
	c, err := loadConfig(writeConfig(t, ok))
	require.NoError(t, err)
	assert.Equal(t, "hk1-cmpt4", c.Engines[0].Name)

	bad := []string{
		`{"engines":[{"name":"a","admin":"unix:///run/a.sock","event_listen":"127.0.0.1:7101"}]}`,
		`{"event_log_net":"unix//e.sock","engines":[{"name":"a","admin":"http://10.0.0.5:2019","event_listen":"127.0.0.1:7101"}]}`,
		`{"event_log_net":"unix//e.sock","engines":[{"name":"a","admin":"unix:///run/a.sock","event_listen":"127.0.0.1:7101"},{"name":"a","admin":"unix:///run/b.sock","event_listen":"127.0.0.1:7102"}]}`,
		`{"event_log_net":"unix//e.sock","access_log_net":"unix//a.sock","engines":[{"name":"a","admin":"unix:///run/a.sock","event_listen":"127.0.0.1:7101"}]}`,
		`{"event_log_net":"unix//e.sock"}`,
	}
	for _, body := range bad {
		_, err := loadConfig(writeConfig(t, `{"listen":"127.0.0.1:9000",`+body[1:]))
		assert.Error(t, err, body)
	}
}
