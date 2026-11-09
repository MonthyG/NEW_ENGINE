package ingest

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"hostinginside/waf/manager/store"
)

func TestListenerStoresStreamedEvents(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &Listener{Addr: "127.0.0.1:0", Store: st, ready: make(chan net.Addr, 1)}
	go l.Run(ctx)
	c, err := net.Dial("tcp", (<-l.ready).String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	line := `{"ts":1761200000,"msg":"hi_event","event":"ip_block","site_id":"s_aaaaaaaaaaaa","client_ip":"1.2.3.4"}`
	// one whole line, then one split across writes with a pause (an idle flush) between
	if _, err := c.Write([]byte(line + "\n" + line[:20])); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := c.Write([]byte(line[20:] + "\nnot json\n")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		evs, err := st.QueryEvents(ctx, store.EventFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) == 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("events = %d, want 2 (the split line rejoined, the junk line skipped)", len(evs))
		}
		time.Sleep(100 * time.Millisecond)
	}
}
