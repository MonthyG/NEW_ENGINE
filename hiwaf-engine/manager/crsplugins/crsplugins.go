// Package crsplugins holds the official OWASP CRS rule-exclusion plugins for
// common web applications ("app profiles"). They are vendored from the
// coreruleset/<app>-rule-exclusions-plugin releases named in Catalog, under
// each one's Apache-2.0 licence, and written to the data directory at start so
// the engine can include them by path.
package crsplugins

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed files
var files embed.FS

// App is one application profile.
type App struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Summary string   `json:"summary"`
	Paths   []string `json:"paths"` // where its admin lives, for the console's hint
	Version string   `json:"version"`
}

// Catalog is the profiles the console offers, in display order.
var Catalog = []App{
	{"wordpress", "WordPress", "Saving posts and pages in both editors, media, menus, widgets and settings. Comment fields are left to WordPress’s own filter.", []string{"/wp-admin/", "/wp-json/", "/wp-login.php"}, "v1.2.0"},
	{"drupal", "Drupal", "Saving content and using the admin forms.", []string{"/node/", "/admin/structure", "/admin/config"}, "v1.0.0"},
	{"nextcloud", "Nextcloud", "File sync and uploads (including WebDAV methods), sharing, and editing documents.", []string{"/remote.php/", "/ocs/", "/index.php/apps/"}, "v1.7.1"},
	{"phpmyadmin", "phpMyAdmin", "Running SQL from its query box and editing rows.", []string{"/phpmyadmin/"}, "v1.1.0"},
	{"dokuwiki", "DokuWiki", "Editing and saving wiki pages.", []string{"/doku.php", "/lib/exe/"}, "v1.0.0"},
	{"phpbb", "phpBB", "Posting, private messages and the admin panel.", []string{"/posting.php", "/ucp.php", "/adm/"}, "v1.0.0"},
	{"xenforo", "XenForo", "Posting, conversations and the admin panel.", []string{"/threads/", "/admin.php"}, "v1.0.0"},
}

// Known reports whether key names a profile.
func Known(key string) bool {
	for _, a := range Catalog {
		if a.Key == key {
			return true
		}
	}
	return false
}

// Stages lists a profile's rule files by when CRS loads them: config and
// before ahead of the rules, after behind them. Names are relative to the
// profile's directory.
type Stages struct{ Config, Before, After []string }

// Files returns key's rule files.
func Files(key string) Stages {
	var s Stages
	ents, _ := fs.ReadDir(files, "files/"+key)
	for _, e := range ents {
		switch n := e.Name(); {
		case strings.HasSuffix(n, "-config.conf"):
			s.Config = append(s.Config, n)
		case strings.HasSuffix(n, "-before.conf"):
			s.Before = append(s.Before, n)
		case strings.HasSuffix(n, "-after.conf"):
			s.After = append(s.After, n)
		}
	}
	return s
}

// Install writes every profile's files under dir/<key>/, replacing what is
// there, so a manager upgrade brings its plugin versions with it.
func Install(dir string) error {
	for _, a := range Catalog {
		dst := filepath.Join(dir, a.Key)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
		ents, err := fs.ReadDir(files, path.Join("files", a.Key))
		if err != nil {
			return fmt.Errorf("plugin %s: %w", a.Key, err)
		}
		want := map[string]bool{}
		for _, e := range ents {
			b, err := files.ReadFile(path.Join("files", a.Key, e.Name()))
			if err != nil {
				return err
			}
			tmp := filepath.Join(dst, "."+e.Name()+".tmp")
			if err := os.WriteFile(tmp, b, 0o644); err != nil {
				return err
			}
			if err := os.Rename(tmp, filepath.Join(dst, e.Name())); err != nil {
				return err
			}
			want[e.Name()] = true
		}
		// drop files an older release had
		old, _ := os.ReadDir(dst)
		for _, e := range old {
			if !want[e.Name()] {
				os.Remove(filepath.Join(dst, e.Name()))
			}
		}
	}
	return nil
}

// Keys returns the catalog's keys, sorted; for validation messages.
func Keys() []string {
	k := make([]string, 0, len(Catalog))
	for _, a := range Catalog {
		k = append(k, a.Key)
	}
	sort.Strings(k)
	return k
}
