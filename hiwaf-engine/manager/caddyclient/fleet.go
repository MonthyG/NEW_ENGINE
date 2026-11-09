package caddyclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Engine is one member of a Fleet, named after the host it runs on.
type Engine struct {
	Name   string
	Client *Client
}

// Fleet drives several engines with one config: in transparent mode there is
// an engine on every compute host. It implements the manager's api.Loader.
//
// Load tries the engines in order until one answers (the canary). If the
// canary rejects the config, Load returns that error and no other engine was
// changed, so the API's rollback stays correct. If it accepts, the rest are
// loaded in parallel; any that fail are marked stale and Run keeps re-pushing
// the last accepted config to them, so one dead host can't block changes.
type Fleet struct {
	Engines []Engine
	Retry   time.Duration // between resyncs of stale engines; default 10s
	Logger  *slog.Logger  // default slog.Default()

	mu    sync.Mutex
	last  any             // the config every engine should run; nil until the first accepted load
	stale map[string]bool // engines that did not take last
}

func (f *Fleet) log() *slog.Logger {
	if f.Logger != nil {
		return f.Logger
	}
	return slog.Default()
}

// Load pushes cfg to every engine (see Fleet).
func (f *Fleet) Load(ctx context.Context, cfg any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stale == nil {
		f.stale = map[string]bool{}
	}
	err := fmt.Errorf("%w: no engines configured", ErrUnreachable)
	canary := -1
	for i, e := range f.Engines {
		err = e.Client.Load(ctx, cfg)
		if errors.Is(err, ErrUnreachable) {
			// It may still apply the load it didn't answer; resync puts it back to last.
			f.stale[e.Name] = true
			continue
		}
		if err != nil {
			return err
		}
		canary = i
		break
	}
	if canary < 0 {
		return err
	}
	f.last = cfg
	delete(f.stale, f.Engines[canary].Name)

	var wg sync.WaitGroup
	var smu sync.Mutex
	for _, e := range f.Engines[canary+1:] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := e.Client.Load(ctx, cfg)
			smu.Lock()
			defer smu.Unlock()
			if err != nil {
				f.stale[e.Name] = true
				f.log().Error("engine missed a config load; retrying in the background", "engine", e.Name, "err", err)
				return
			}
			delete(f.stale, e.Name)
		}()
	}
	wg.Wait()
	return nil
}

// Run re-pushes the last accepted config to stale engines until ctx is done.
func (f *Fleet) Run(ctx context.Context) {
	iv := f.Retry
	if iv <= 0 {
		iv = 10 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.resync(ctx)
		}
	}
}

func (f *Fleet) resync(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.last == nil {
		return
	}
	for _, e := range f.Engines {
		if !f.stale[e.Name] {
			continue
		}
		if err := e.Client.Load(ctx, f.last); err == nil {
			delete(f.stale, e.Name)
			f.log().Info("engine caught up with the saved config", "engine", e.Name)
		}
	}
}

// Health reports each unreachable or stale engine; nil when all are current.
func (f *Fleet) Health(ctx context.Context) error {
	f.mu.Lock()
	stale := make(map[string]bool, len(f.stale))
	for k, v := range f.stale {
		stale[k] = v
	}
	f.mu.Unlock()
	var errs []error
	for _, e := range f.Engines {
		if _, err := e.Client.WaitRooms(ctx); err != nil {
			errs = append(errs, fmt.Errorf("engine %s: %w", e.Name, err))
		} else if stale[e.Name] {
			errs = append(errs, fmt.Errorf("engine %s: running an old config", e.Name))
		}
	}
	return errors.Join(errs...)
}

// Bans merges every engine's bans; an IP banned on several engines is listed
// once, with its latest expiry. It fails only if no engine answered.
func (f *Fleet) Bans(ctx context.Context, siteID string) (map[string][]Ban, error) {
	merged := map[string]map[string]Ban{}
	err := f.each(func(c *Client) error {
		b, err := c.Bans(ctx, siteID)
		for site, list := range b {
			if merged[site] == nil {
				merged[site] = map[string]Ban{}
			}
			for _, x := range list {
				if old, ok := merged[site][x.IP]; !ok || x.Until.After(old.Until) {
					merged[site][x.IP] = x
				}
			}
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string][]Ban, len(merged))
	for site, m := range merged {
		for _, x := range m {
			out[site] = append(out[site], x)
		}
	}
	return out, nil
}

// Unban lifts the ban on every engine; it reports whether any engine had it.
func (f *Fleet) Unban(ctx context.Context, siteID, ip string) (bool, error) {
	found := false
	err := f.each(func(c *Client) error {
		ok, err := c.Unban(ctx, siteID, ip)
		found = found || ok
		return err
	})
	return found, err
}

// WaitRooms sums waiting-room occupancy over the engines.
func (f *Fleet) WaitRooms(ctx context.Context) (map[string]WaitRoom, error) {
	out := map[string]WaitRoom{}
	err := f.each(func(c *Client) error {
		m, err := c.WaitRooms(ctx)
		for site, w := range m {
			sum := out[site]
			sum.Active += w.Active
			sum.Waiting += w.Waiting
			out[site] = sum
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// each calls fn for every engine in turn and returns the first error only if
// every call failed.
func (f *Fleet) each(fn func(*Client) error) error {
	var first error
	answered := false
	for _, e := range f.Engines {
		if err := fn(e.Client); err != nil {
			if first == nil {
				first = fmt.Errorf("engine %s: %w", e.Name, err)
			}
			continue
		}
		answered = true
	}
	if answered {
		return nil
	}
	if first == nil {
		first = fmt.Errorf("%w: no engines configured", ErrUnreachable)
	}
	return first
}
