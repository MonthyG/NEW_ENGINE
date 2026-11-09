// Package ratelimit is a pure, Caddy-free sliding-window limiter with bans.
package ratelimit

import (
	"sync"
	"time"
)

// Limit is one rate-limit rule: more than Requests events in WindowSec bans
// the client for BanSec.
type Limit struct {
	Requests  int `json:"requests"`
	WindowSec int `json:"window_sec"`
	BanSec    int `json:"ban_sec"`
}

// Kind is the class of event being counted.
type Kind int

const (
	KindAccess Kind = iota
	KindAttack
	KindError
)

type windowKey struct {
	kind Kind
	ip   string
}

type window struct {
	start  int64 // unix seconds, truncated to lenSec
	lenSec int64
	cur    int
	prev   int
}

// maxWindows caps the counters one State keeps, so a flood from many
// distinct sources can't grow memory without bound between sweeps. At the
// cap, Record drops idle counters and then, if still full, an arbitrary
// tenth of the rest; bans are kept.
const maxWindows = 100_000

// State holds bans and counters. It is safe for concurrent use.
type State struct {
	mu      sync.Mutex
	bans    map[string]time.Time
	windows map[windowKey]*window
}

func NewState() *State {
	return &State{
		bans:    make(map[string]time.Time),
		windows: make(map[windowKey]*window),
	}
}

// BannedUntil reports the ban expiry for ip if it is banned at now.
func (s *State) BannedUntil(ip string, now time.Time) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.bans[ip]
	if !ok || !until.After(now) {
		return time.Time{}, false
	}
	return until, true
}

// Record counts one event of kind k for ip. When the sliding-window estimate
// exceeds lim.Requests the ip is banned until now+BanSec and the window is
// reset. An already-banned ip is not counted and returns its existing expiry
// with newlyBanned=false. A non-positive Requests or WindowSec disables the limit.
func (s *State) Record(k Kind, ip string, lim Limit, now time.Time) (until time.Time, newlyBanned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if u, ok := s.bans[ip]; ok && u.After(now) {
		return u, false
	}
	if lim.Requests <= 0 || lim.WindowSec <= 0 {
		return time.Time{}, false
	}

	wl := int64(lim.WindowSec)
	ws := now.Unix() - now.Unix()%wl
	key := windowKey{k, ip}
	w := s.windows[key]
	if w == nil {
		if len(s.windows) >= maxWindows {
			s.evictLocked(now.Unix())
		}
		w = &window{start: ws, lenSec: wl}
		s.windows[key] = w
	}
	w.lenSec = wl
	if ws > w.start {
		if ws-w.start == wl {
			w.prev = w.cur
		} else {
			w.prev = 0
		}
		w.cur = 0
		w.start = ws
	}

	elapsed := now.Sub(time.Unix(w.start, 0)).Seconds()
	weight := 1 - elapsed/float64(wl)
	// Clamp to [0,1]: elapsed is negative when the clock steps back, or when a
	// reload grows WindowSec so ws no longer advances past the old start.
	if weight < 0 {
		weight = 0
	} else if weight > 1 {
		weight = 1
	}
	w.cur++
	estimate := float64(w.cur) + float64(w.prev)*weight
	if estimate > float64(lim.Requests) {
		until = now.Add(time.Duration(lim.BanSec) * time.Second)
		s.bans[ip] = until
		w.cur, w.prev = 0, 0
		return until, true
	}
	return time.Time{}, false
}

// Unban removes a ban; it reports whether one existed.
func (s *State) Unban(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.bans[ip]
	delete(s.bans, ip)
	return ok
}

// Bans returns a copy of the unexpired bans.
func (s *State) Bans(now time.Time) map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]time.Time, len(s.bans))
	for ip, until := range s.bans {
		if until.After(now) {
			out[ip] = until
		}
	}
	return out
}

// Sweep drops expired bans and windows idle for more than two window lengths.
func (s *State) Sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, until := range s.bans {
		if !until.After(now) {
			delete(s.bans, ip)
		}
	}
	s.dropIdleLocked(now.Unix())
}

// dropIdleLocked drops windows idle for more than two window lengths.
func (s *State) dropIdleLocked(n int64) {
	for key, w := range s.windows {
		if n-w.start > 2*w.lenSec {
			delete(s.windows, key)
		}
	}
}

// evictLocked makes room below maxWindows: idle windows first, then an
// arbitrary tenth (Go's map order is unspecified, so this isn't predictable
// by a client).
func (s *State) evictLocked(n int64) {
	s.dropIdleLocked(n)
	if len(s.windows) < maxWindows {
		return
	}
	drop := maxWindows / 10
	for key := range s.windows {
		if drop == 0 {
			break
		}
		delete(s.windows, key)
		drop--
	}
}
