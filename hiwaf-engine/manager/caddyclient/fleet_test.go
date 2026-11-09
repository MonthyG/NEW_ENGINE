package caddyclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// fakeEngine is a Caddy admin API stand-in: status answers /load, down drops
// every connection (unreachable), and loads counts the loads it took.
type fakeEngine struct {
	srv    *httptest.Server
	status atomic.Int32
	down   atomic.Bool
	loads  atomic.Int32
	bans   string
}

func newFakeEngine(t *testing.T) *fakeEngine {
	f := &fakeEngine{bans: `{}`}
	f.status.Store(200)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.down.Load() {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		switch r.URL.Path {
		case "/load":
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(int(f.status.Load()))
			if f.status.Load() == 200 {
				f.loads.Add(1)
			}
		case "/hi/bans":
			io.WriteString(w, f.bans)
		case "/hi/waitroom":
			io.WriteString(w, `{"s1":{"active":2,"waiting":1}}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func fleetOf(engines ...*fakeEngine) *Fleet {
	f := &Fleet{}
	for i, e := range engines {
		f.Engines = append(f.Engines, Engine{Name: string(rune('a' + i)), Client: &Client{BaseURL: e.srv.URL}})
	}
	return f
}

func TestFleetCanaryRejectChangesNothingElse(t *testing.T) {
	a, b := newFakeEngine(t), newFakeEngine(t)
	a.status.Store(400)
	err := fleetOf(a, b).Load(context.Background(), map[string]any{})
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("err = %v, want the canary's LoadError", err)
	}
	if b.loads.Load() != 0 {
		t.Fatal("an engine after the rejecting canary was loaded")
	}
}

func TestFleetDeadEngineGoesStaleThenCatchesUp(t *testing.T) {
	a, b, c := newFakeEngine(t), newFakeEngine(t), newFakeEngine(t)
	a.down.Store(true) // the first engine can't be the canary
	c.down.Store(true) // one after the canary misses the load
	f := fleetOf(a, b, c)
	if err := f.Load(context.Background(), map[string]any{"v": 1}); err != nil {
		t.Fatalf("one live engine should be enough: %v", err)
	}
	if b.loads.Load() != 1 || !f.stale["a"] || !f.stale["c"] || f.stale["b"] {
		t.Fatalf("loads b=%d stale=%v", b.loads.Load(), f.stale)
	}
	if f.Health(context.Background()) == nil {
		t.Fatal("Health hides dead engines")
	}
	a.down.Store(false)
	c.down.Store(false)
	f.resync(context.Background())
	if a.loads.Load() != 1 || c.loads.Load() != 1 || len(f.stale) != 0 {
		t.Fatalf("after resync loads a=%d c=%d stale=%v", a.loads.Load(), c.loads.Load(), f.stale)
	}
	if err := f.Health(context.Background()); err != nil {
		t.Fatalf("Health after catch-up: %v", err)
	}
}

func TestFleetAllDownIsUnreachable(t *testing.T) {
	a := newFakeEngine(t)
	a.down.Store(true)
	f := fleetOf(a)
	if err := f.Load(context.Background(), map[string]any{}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
	if f.last != nil {
		t.Fatal("a load nobody took became the resync config")
	}
	if err := (&Fleet{}).Load(context.Background(), nil); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("empty fleet: err = %v", err)
	}
}

func TestFleetMergesBansAndWaitRooms(t *testing.T) {
	a, b, c := newFakeEngine(t), newFakeEngine(t), newFakeEngine(t)
	a.bans = `{"s1":[{"ip":"1.2.3.4","until":"2030-01-01T00:00:00Z"}]}`
	b.bans = `{"s1":[{"ip":"1.2.3.4","until":"2031-01-01T00:00:00Z"},{"ip":"5.6.7.8","until":"2030-01-01T00:00:00Z"}]}`
	c.down.Store(true)
	f := fleetOf(a, b, c)
	bans, err := f.Bans(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(bans["s1"]) != 2 {
		t.Fatalf("bans = %v, want 1.2.3.4 once and 5.6.7.8", bans)
	}
	for _, x := range bans["s1"] {
		if x.IP == "1.2.3.4" && x.Until.Year() != 2031 {
			t.Fatalf("kept the earlier expiry: %v", x)
		}
	}
	w, err := f.WaitRooms(context.Background())
	if err != nil || w["s1"].Active != 4 || w["s1"].Waiting != 2 {
		t.Fatalf("waitrooms = %v, %v", w, err)
	}
	a.down.Store(true)
	b.down.Store(true)
	if _, err := f.Bans(context.Background(), ""); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("all down: err = %v", err)
	}
}
