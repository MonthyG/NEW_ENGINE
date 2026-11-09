package waitroom

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Admin{})
}

// Admin is the admin.api.hi_waitroom module:
//
//	GET /hi/waitroom → {"<siteID>":{"active":N,"waiting":N}}
//
// The manager also uses it as the engine's health check.
type Admin struct{}

// CaddyModule returns the Caddy module information.
func (Admin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.hi_waitroom",
		New: func() caddy.Module { return new(Admin) },
	}
}

// Routes implements caddy.AdminRouter.
func (Admin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{{Pattern: "/hi/waitroom", Handler: caddy.AdminHandlerFunc(handle)}}
}

// Counts is one site's waiting-room occupancy.
type Counts struct {
	Active  int `json:"active"`
	Waiting int `json:"waiting"`
}

func handle(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: errors.New("method not allowed")}
	}
	roomsMu.Lock()
	sites := make([]string, 0, len(rooms))
	for s := range rooms {
		sites = append(sites, s)
	}
	roomsMu.Unlock()
	out := map[string]Counts{}
	for _, s := range sites {
		a, q := Stats(s)
		out[s] = Counts{Active: a, Waiting: q}
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(out)
}

var _ caddy.AdminRouter = Admin{}
