package ratelimit

import (
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// sweepEvery is how often a pooled State drops expired bans and idle windows.
const sweepEvery = 30 * time.Second

// pool holds one State per site ID. A config reload provisions the new
// handlers (acquire, refcount 2) before cleaning up the old ones (release,
// refcount 1), so bans and counters survive reloads.
var pool = caddy.NewUsagePool()

// pooledState is a State plus its sweeper goroutine; it is the pool value.
type pooledState struct {
	*State
	stop chan struct{}
	once sync.Once
}

// Destruct stops the sweeper. The pool calls it when the last user releases.
func (p *pooledState) Destruct() error {
	p.once.Do(func() { close(p.stop) })
	return nil
}

func (p *pooledState) sweep() {
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case now := <-t.C:
			p.Sweep(now)
		}
	}
}

// acquire returns the shared State for siteID, creating it (and starting its
// sweeper) on first use. Every acquire must be paired with one release.
func acquire(siteID string) (*State, error) {
	v, _, err := pool.LoadOrNew(siteID, func() (caddy.Destructor, error) {
		p := &pooledState{State: NewState(), stop: make(chan struct{})}
		go p.sweep()
		return p, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*pooledState).State, nil
}

// release drops one reference to siteID's State; the last one destroys it.
func release(siteID string) error {
	_, err := pool.Delete(siteID)
	return err
}

// lookup returns siteID's State without taking a reference.
func lookup(siteID string) (*State, bool) {
	var st *State
	pool.Range(func(k, v any) bool {
		if k == siteID {
			st = v.(*pooledState).State
			return false
		}
		return true
	})
	return st, st != nil
}
