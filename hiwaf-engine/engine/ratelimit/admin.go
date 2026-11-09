package ratelimit

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// BanAdmin is the admin.api.hi_bans module: it lists and lifts bans.
//
//	GET    /hi/bans[?site=ID]   → {"<siteID>":[{"ip":"…","until":"RFC3339"}]}
//	DELETE /hi/bans?site=&ip=   → 204, or 404 if the ip is not banned
//
// An IPv6 ban is listed as its /64 ("2001:db8::/64"); DELETE takes that
// prefix or any address inside it.
type BanAdmin struct{}

// CaddyModule returns the Caddy module information.
func (BanAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.hi_bans",
		New: func() caddy.Module { return new(BanAdmin) },
	}
}

// Routes implements caddy.AdminRouter.
func (BanAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{{Pattern: "/hi/bans", Handler: caddy.AdminHandlerFunc(handleBans)}}
}

type banEntry struct {
	IP    string `json:"ip"`
	Until string `json:"until"`
}

func handleBans(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		return listBans(w, r)
	case http.MethodDelete:
		return deleteBan(w, r)
	default:
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: errors.New("method not allowed")}
	}
}

func listBans(w http.ResponseWriter, r *http.Request) error {
	now := time.Now()
	out := map[string][]banEntry{}
	if site := r.URL.Query().Get("site"); site != "" {
		if st, ok := lookup(site); ok {
			out[site] = entries(st, now)
		}
	} else {
		pool.Range(func(k, v any) bool {
			out[k.(string)] = entries(v.(*pooledState).State, now)
			return true
		})
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(out)
}

func entries(st *State, now time.Time) []banEntry {
	bans := st.Bans(now)
	list := make([]banEntry, 0, len(bans))
	for ip, until := range bans {
		list = append(list, banEntry{IP: ip, Until: until.UTC().Format(time.RFC3339)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })
	return list
}

func deleteBan(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	site, ip := q.Get("site"), q.Get("ip")
	if site == "" || ip == "" {
		return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: errors.New("site and ip are required")}
	}
	ip = adminKey(ip) // an IPv6 ban covers the whole /64
	st, ok := lookup(site)
	if ok {
		_, ok = st.BannedUntil(ip, time.Now())
	}
	if !ok || !st.Unban(ip) {
		return caddy.APIError{HTTPStatus: http.StatusNotFound, Err: errors.New("not banned")}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

var _ caddy.AdminRouter = BanAdmin{}
