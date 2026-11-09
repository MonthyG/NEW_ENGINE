package ingest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"hostinginside/waf/manager/store"
)

// Listener receives a log that a remote engine streams with Caddy's net
// writer (carried to the manager over an SSH tunnel) and stores its lines the
// way Tailer does. Unlike a file there is no offset: lines the engine writes
// while nothing is listening are dropped by Caddy.
type Listener struct {
	Addr    string // TCP address to listen on, such as 127.0.0.1:7101
	Store   *store.Store
	Access  bool                   // the stream is a Caddy access log
	Country func(ip string) string // optional GeoIP lookup
	Logger  *slog.Logger           // default slog.Default()

	ready chan net.Addr // tests: receives the bound address
}

// Run accepts connections until ctx is done.
func (l *Listener) Run(ctx context.Context) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", l.Addr)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	if l.ready != nil {
		l.ready <- ln.Addr()
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go l.serve(ctx, c)
	}
}

// serve stores c's lines in batches: when a batch fills, and after a second
// with nothing new.
func (l *Listener) serve(ctx context.Context, c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	log := l.Logger
	if log == nil {
		log = slog.Default()
	}
	country := func(ip string) string {
		if l.Country == nil || ip == "" {
			return ""
		}
		return l.Country(ip)
	}

	var evs []store.Event
	var reqs []store.Request
	flush := func() {
		if len(evs)+len(reqs) == 0 {
			return
		}
		fctx := context.WithoutCancel(ctx) // the last batch is stored even while shutting down
		if err := l.Store.InsertEvents(fctx, evs); err != nil {
			log.Error("ingest", "addr", l.Addr, "err", err)
		}
		if err := l.Store.InsertRequests(fctx, reqs); err != nil {
			log.Error("ingest", "addr", l.Addr, "err", err)
		}
		evs, reqs = evs[:0], reqs[:0]
	}
	defer flush()

	r := bufio.NewReaderSize(c, 64<<10)
	var buf []byte
	skipping := false // current line exceeded maxLineBytes: discard it
	for {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		chunk, err := r.ReadSlice('\n')
		if !skipping {
			buf = append(buf, chunk...)
			if len(buf) > maxLineBytes {
				skipping, buf = true, buf[:0]
			}
		}
		var ne net.Error
		switch {
		case err == nil:
			if !skipping {
				evs, reqs = parseInto(bytes.TrimRight(buf, "\r\n"), l.Access, country, evs, reqs)
			}
			buf, skipping = buf[:0], false
			if len(evs)+len(reqs) >= batchSize {
				flush()
			}
		case errors.Is(err, bufio.ErrBufferFull):
		case errors.As(err, &ne) && ne.Timeout():
			flush() // a partial line stays in buf until the rest arrives
		default:
			return // EOF or closed; Caddy reconnects
		}
	}
}
