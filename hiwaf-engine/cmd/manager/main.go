// Command manager is the HostingInside WAF control plane: it serves the web
// console and the REST API, keeps sites in SQLite, pushes compiled configs to
// the Caddy engine and ingests the engine's security events and access log.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/geoip2-golang"

	"hostinginside/waf/manager/alert"
	"hostinginside/waf/manager/api"
	"hostinginside/waf/manager/backup"
	"hostinginside/waf/manager/caddyclient"
	"hostinginside/waf/manager/compile"
	"hostinginside/waf/manager/console"
	"hostinginside/waf/manager/crsplugins"
	"hostinginside/waf/manager/ingest"
	"hostinginside/waf/manager/store"
)

type config struct {
	Listen             string   `json:"listen"`
	DBPath             string   `json:"db_path"`
	DataDir            string   `json:"data_dir"`
	CaddyAdmin         string   `json:"caddy_admin"`
	SkipDomainCheck    bool     `json:"skip_domain_check"` // let projects add domains without a TXT proof (test servers)
	EventLog           string   `json:"event_log"`
	AccessLog          string   `json:"access_log"`
	APIKeys            []string `json:"api_keys"`
	HTTPPort           int      `json:"http_port"`
	HTTPSPort          int      `json:"https_port"`
	GeoIPDB            string   `json:"geoip_db"`
	FeedsDir           string   `json:"feeds_dir"`
	StaticDir          string   `json:"static_dir"`
	TrustedProxies     []string `json:"trusted_proxies"`
	ACMEInternal       bool     `json:"acme_internal"`
	TLSCert            string   `json:"tls_cert"`        // console certificate (PEM)
	TLSKey             string   `json:"tls_key"`         // console key (PEM)
	SelfSignedTLS      bool     `json:"self_signed_tls"` // generate tls_cert/tls_key in data_dir if missing
	RetentionDays      int      `json:"retention_days"`  // access-log rows; default 7
	EventRetentionDays int      `json:"event_retention_days"`
	BackupDir          string   `json:"backup_dir"`   // default <data_dir>/backups
	BackupHours        int      `json:"backup_hours"` // between backups; default 24, -1 = no scheduled backups
	BackupKeep         int      `json:"backup_keep"`  // newest backups kept; default 7
	RulesetsDir        string   `json:"rulesets_dir"` // unpacked CRS releases; default <data_dir>/rulesets
	PluginsDir         string   `json:"plugins_dir"`  // app profiles' CRS plugins, rewritten at start; default <data_dir>/crs-plugins

	// Transparent mode: one engine per compute host, each reached over an SSH
	// tunnel. caddy_admin, event_log and access_log are then the paths as the
	// engines see them; empty engines = the single local engine at caddy_admin.
	Engines      []engineConfig `json:"engines"`
	EventLogNet  string         `json:"event_log_net"`  // where engines stream events, as a Caddy address (unix//data/events.sock)
	AccessLogNet string         `json:"access_log_net"` // the same for the access log; empty = no access log
}

// engineConfig is one remote engine of a fleet.
type engineConfig struct {
	Name         string `json:"name"`          // the compute host, for logs and alerts
	Admin        string `json:"admin"`         // the tunnelled admin socket on this host, unix:///run/hiwaf/<name>.sock
	EventListen  string `json:"event_listen"`  // TCP address here that the tunnel delivers its event stream to
	AccessListen string `json:"access_listen"` // the same for its access log; required with access_log_net
}

const secretKey = "challenge_secret"

// devKey is the API key shipped in examples/manager.json. It is accepted only
// while the API listens on a loopback address.
const devKey = "change-me-dev-key"

// loopback reports whether a listen address binds only to the local host.
// An empty host (":9000") binds every interface and is not loopback.
func loopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loadConfig(path string) (config, error) {
	var c config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&c.Listen, ":9000")
	def(&c.CaddyAdmin, "http://localhost:2019") // Caddy's own default admin address: pushing a different spelling makes Caddy try to bind the port twice
	def(&c.EventLog, "events.log")
	def(&c.DBPath, "waf.db")
	def(&c.DataDir, filepath.Dir(c.DBPath))
	if c.HTTPPort == 0 {
		c.HTTPPort = 80
	}
	if c.HTTPSPort == 0 {
		c.HTTPSPort = 443
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 7
	}
	if c.EventRetentionDays == 0 {
		c.EventRetentionDays = 30
	}
	def(&c.BackupDir, filepath.Join(c.DataDir, "backups"))
	def(&c.RulesetsDir, filepath.Join(c.DataDir, "rulesets"))
	def(&c.PluginsDir, filepath.Join(c.DataDir, "crs-plugins"))
	if c.BackupHours == 0 {
		c.BackupHours = 24
	}
	var keys []string
	for _, k := range c.APIKeys {
		if k != "" {
			keys = append(keys, k)
		}
	}
	c.APIKeys = keys
	if !loopback(c.Listen) {
		for _, k := range keys {
			if k == devKey {
				return c, fmt.Errorf("%s: api key %q is the public example key; replace it or listen on a loopback address (127.0.0.1, ::1, localhost), not %q", path, devKey, c.Listen)
			}
		}
	}
	if (c.TLSCert == "") != (c.TLSKey == "") && !c.SelfSignedTLS {
		return c, fmt.Errorf("%s: tls_cert and tls_key must be set together", path)
	}
	if c.SelfSignedTLS {
		def(&c.TLSCert, filepath.Join(c.DataDir, "console.crt"))
		def(&c.TLSKey, filepath.Join(c.DataDir, "console.key"))
	}
	if err := checkEngines(c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	// Caddy runs with its own working directory, so paths it opens are made
	// absolute here; the manager reads the logs at the same paths.
	for _, p := range []*string{&c.EventLog, &c.AccessLog, &c.GeoIPDB, &c.FeedsDir, &c.StaticDir, &c.BackupDir, &c.RulesetsDir, &c.PluginsDir} {
		if *p == "" {
			continue
		}
		if *p, err = filepath.Abs(*p); err != nil {
			return c, err
		}
	}
	return c, nil
}

// checkEngines validates the fleet settings: each engine needs a name, a
// tunnelled unix admin socket and a place to receive its logs.
func checkEngines(c config) error {
	if len(c.Engines) == 0 {
		if c.EventLogNet != "" || c.AccessLogNet != "" {
			return errors.New("event_log_net and access_log_net need engines")
		}
		return nil
	}
	if c.EventLogNet == "" {
		return errors.New("engines need event_log_net: the manager can't read a remote engine's log files")
	}
	seen := map[string]bool{}
	for i, e := range c.Engines {
		switch {
		case e.Name == "" || seen[e.Name]:
			return fmt.Errorf("engines[%d]: name is empty or used twice", i)
		case !strings.HasPrefix(e.Admin, "unix:///"):
			return fmt.Errorf("engines[%d]: admin must be the tunnelled socket, unix:///run/hiwaf/%s.sock; the admin API has no login, so never reach it over TCP", i, e.Name)
		case e.EventListen == "":
			return fmt.Errorf("engines[%d]: event_listen is required", i)
		case (e.AccessListen == "") != (c.AccessLogNet == ""):
			return fmt.Errorf("engines[%d]: access_listen and access_log_net go together", i)
		}
		seen[e.Name] = true
	}
	return nil
}

// challengeSecret returns the stored secret, creating it on first start.
func challengeSecret(ctx context.Context, st *store.Store) (string, error) {
	s, ok, err := st.Setting(ctx, secretKey)
	if err != nil || ok {
		return s, err
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails since Go 1.24
	s = base64.StdEncoding.EncodeToString(b)
	return s, st.SetSetting(ctx, secretKey, s)
}

// ensureSelfSigned writes a 10-year self-signed ECDSA certificate for the
// console if certPath doesn't exist yet.
func ensureSelfSigned(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "HostingInside WAF console", Organization: []string{"HostingInside"}},
		DNSNames:     []string{"localhost", host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func main() {
	cfgPath := flag.String("config", "manager.json", "path to the manager config file")
	reset := flag.Bool("resetadmin", false, "set a new random password for the console user admin and exit")
	restore := flag.String("restore", "", "replace the database with this backup file and exit; stop the manager first")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)
	var err error
	switch {
	case *reset:
		err = resetAdmin(*cfgPath)
	case *restore != "":
		err = restoreDB(*cfgPath, *restore)
	default:
		err = run(*cfgPath, log)
	}
	if err != nil {
		log.Error("manager", "err", err)
		os.Exit(1)
	}
}

func resetAdmin(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	pw, err := api.ResetAdmin(context.Background(), st)
	if err != nil {
		return err
	}
	fmt.Printf("Console user: admin\nNew password: %s\n", pw)
	return nil
}

// restoreDB replaces the database with a backup. The current database is kept
// beside it as <db>.before-restore-<time>. The manager must be stopped: it
// holds the database open.
func restoreDB(cfgPath, file string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := store.CheckFile(ctx, file); err != nil {
		return fmt.Errorf("%s is not a usable backup: %w", file, err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.DBPath); err == nil {
		// opening and closing folds the write-ahead log into the file, so
		// the copy kept aside is complete
		st, err := store.Open(cfg.DBPath)
		if err != nil {
			return err
		}
		st.Close()
		aside := cfg.DBPath + ".before-restore-" + time.Now().UTC().Format("20060102-150405")
		if err := os.Rename(cfg.DBPath, aside); err != nil {
			return err
		}
		fmt.Printf("Current database kept as %s\n", aside)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(cfg.DBPath + suffix)
	}
	if err := os.WriteFile(cfg.DBPath, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("Restored %s. Start the manager; it pushes the restored sites to the engine.\n", file)
	return nil
}

// consolePort returns the port of a listen address, or 0.
func consolePort(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// bootstrapListen is Caddy's default admin address, where a fresh engine
// listens until the first config load moves its admin API to the socket.
const bootstrapListen = "localhost:2019"

// adminAddress turns caddy_admin into the admin listen address pushed to
// Caddy and, for a unix socket, the TCP URL used until the socket exists.
// The socket (owner-only, in the data volume) keeps the unauthenticated admin
// API away from anything else on the host network.
func adminAddress(s string) (listen, bootstrap string, err error) {
	u, err := url.Parse(s)
	switch {
	case err == nil && u.Scheme == "unix" && u.Host == "" && strings.HasPrefix(u.Path, "/"):
		return "unix/" + u.Path + "|0600", "http://" + bootstrapListen, nil
	case err == nil && u.Scheme == "http" && u.Host != "":
		return u.Host, "", nil
	}
	return "", "", fmt.Errorf("caddy_admin must be unix:///path/to/admin.sock or a URL such as http://localhost:2019, got %q", s)
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	adminListen, bootstrap, err := adminAddress(cfg.CaddyAdmin)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	secret, err := challengeSecret(ctx, st)
	if err != nil {
		return fmt.Errorf("challenge secret: %w", err)
	}
	note := filepath.Join(cfg.DataDir, "initial-admin.txt")
	if pw, err := api.EnsureAdmin(ctx, st); err != nil {
		return fmt.Errorf("console admin: %w", err)
	} else if pw != "" {
		_ = os.WriteFile(note, []byte("Console user: admin\nPassword: "+pw+"\n"), 0o600)
		log.Warn("created console user admin; change its password after the first login",
			"password", pw, "also_written_to", note)
	} else if gone, err := api.CleanAdminNote(ctx, st, note); err != nil {
		log.Warn("could not check the first-password file", "file", note, "err", err)
	} else if gone {
		log.Info("deleted the first-password file: admin's password has changed", "file", note)
	}
	if cfg.StaticDir != "" {
		if err := os.MkdirAll(cfg.StaticDir, 0o755); err != nil {
			return fmt.Errorf("static_dir: %w", err)
		}
	}

	var reserved []int
	for _, a := range []string{adminListen, bootstrapListen} {
		if _, p, err := net.SplitHostPort(a); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				reserved = append(reserved, n)
			}
		}
	}
	if n := consolePort(cfg.Listen); n > 0 {
		reserved = append(reserved, n)
	}
	opt := compile.Options{
		AdminListen:     adminListen,
		HTTPPort:        cfg.HTTPPort,
		HTTPSPort:       cfg.HTTPSPort,
		EventLog:        cfg.EventLog,
		AccessLog:       cfg.AccessLog,
		EventLogNet:     cfg.EventLogNet,
		AccessLogNet:    cfg.AccessLogNet,
		ChallengeSecret: secret,
		GeoIPDB:         cfg.GeoIPDB,
		FeedsDir:        cfg.FeedsDir,
		StaticDir:       cfg.StaticDir,
		TrustedProxies:  cfg.TrustedProxies,
		ACMEInternal:    cfg.ACMEInternal,
		ReservedPorts:   reserved,
		Transparent:     len(cfg.Engines) > 0,
	}
	var engine api.Loader
	var probe func(context.Context) error
	var fleet *caddyclient.Fleet
	if len(cfg.Engines) > 0 {
		fleet = &caddyclient.Fleet{Logger: log}
		for _, e := range cfg.Engines {
			// No Bootstrap: a fresh engine's fallback TCP address is on its own host, not here.
			fleet.Engines = append(fleet.Engines, caddyclient.Engine{Name: e.Name, Client: &caddyclient.Client{BaseURL: e.Admin}})
		}
		engine, probe = fleet, fleet.Health
	} else {
		c := &caddyclient.Client{BaseURL: cfg.CaddyAdmin, Bootstrap: bootstrap}
		engine = c
		probe = func(ctx context.Context) error {
			_, err := c.WaitRooms(ctx)
			return err
		}
	}
	a := api.New(st, engine, opt, cfg.APIKeys)
	if !cfg.SkipDomainCheck {
		a.SetDomainCheck(net.DefaultResolver.LookupTXT)
	}
	host, _ := os.Hostname()
	notifier := &alert.Notifier{Store: st, Host: host, Log: log}
	watcher := &alert.Watcher{Notifier: notifier, Probe: probe}
	backups := &backup.Backups{Store: st, Dir: cfg.BackupDir, Every: time.Duration(cfg.BackupHours) * time.Hour,
		Keep: cfg.BackupKeep, Log: log, Failed: func(err error) {
			notifier.Notify("backup_failed", "the scheduled database backup failed: "+err.Error())
		}}
	// the engine reads the app profiles from here; they ship with this binary
	if err := crsplugins.Install(cfg.PluginsDir); err != nil {
		return fmt.Errorf("plugins_dir: %w", err)
	}
	a.SetOps(api.Ops{RulesetsDir: cfg.RulesetsDir, PluginsDir: cfg.PluginsDir, Backups: backups, Notifier: notifier, Watcher: watcher})
	a.SetAdminNote(note)

	syncCtx, cancel := context.WithTimeout(ctx, time.Minute)
	if err := a.Sync(syncCtx); err != nil {
		log.Warn("initial config push failed; the API is up but changes will fail until the engine is reachable", "err", err)
		go retrySync(ctx, a, log)
	} else {
		log.Info("config pushed to engine", "admin", cfg.CaddyAdmin)
	}
	cancel()

	var country func(string) string
	if cfg.GeoIPDB != "" {
		geo, err := geoip2.Open(cfg.GeoIPDB)
		if err != nil {
			return fmt.Errorf("geoip_db: %w", err)
		}
		defer geo.Close()
		country = func(ip string) string {
			p := net.ParseIP(ip)
			if p == nil {
				return ""
			}
			rec, err := geo.Country(p)
			if err != nil || rec == nil {
				return ""
			}
			return strings.ToUpper(rec.Country.IsoCode)
		}
	}

	done := make(chan struct{}, 6)
	go func() {
		defer func() { done <- struct{}{} }()
		if fleet != nil {
			return // remote engines stream their logs to the listeners below
		}
		_ = (&ingest.Tailer{Path: cfg.EventLog, Store: st, Logger: log, Country: country}).Run(ctx)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		if cfg.AccessLog == "" || fleet != nil {
			return
		}
		_ = (&ingest.Tailer{Path: cfg.AccessLog, Store: st, Logger: log, Access: true,
			OffsetKey: "access_offset", Country: country}).Run(ctx)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		if fleet != nil {
			runFleet(ctx, fleet, cfg.Engines, st, country, log)
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		purge(ctx, st, cfg, log)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		watcher.Run(ctx)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		if cfg.BackupHours > 0 {
			backups.Run(ctx)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/api/", a.Handler())
	mux.Handle("/", console.Handler())
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // static site uploads
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	if cfg.SelfSignedTLS {
		if err := ensureSelfSigned(cfg.TLSCert, cfg.TLSKey); err != nil {
			return fmt.Errorf("self-signed console certificate: %w", err)
		}
	}
	go func() {
		if cfg.TLSCert != "" {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			log.Info("console listening", "url", "https://"+displayAddr(cfg.Listen))
			errc <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
			return
		}
		log.Info("console listening", "url", "http://"+displayAddr(cfg.Listen))
		errc <- srv.ListenAndServe()
	}()

	select {
	case err = <-errc:
		stop()
	case <-ctx.Done():
		log.Info("shutting down")
		shCtx, shCancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = srv.Shutdown(shCtx)
		shCancel()
	}
	for i := 0; i < cap(done); i++ {
		<-done
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// runFleet resyncs stale engines and receives every engine's log streams
// until ctx is done.
func runFleet(ctx context.Context, fleet *caddyclient.Fleet, engines []engineConfig, st *store.Store, country func(string) string, log *slog.Logger) {
	var wg sync.WaitGroup
	wg.Go(func() { fleet.Run(ctx) })
	for _, e := range engines {
		ls := []*ingest.Listener{{Addr: e.EventListen, Store: st, Logger: log, Country: country}}
		if e.AccessListen != "" {
			ls = append(ls, &ingest.Listener{Addr: e.AccessListen, Store: st, Logger: log, Country: country, Access: true})
		}
		for _, l := range ls {
			wg.Go(func() {
				if err := l.Run(ctx); err != nil && ctx.Err() == nil {
					log.Error("engine log listener stopped; its events are not being stored", "engine", e.Name, "addr", l.Addr, "err", err)
				}
			})
		}
	}
	wg.Wait()
}

func displayAddr(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "<server-ip>" + listen
	}
	return listen
}

// retrySync pushes the config every 5 s until it succeeds; Caddy keeps
// serving its last config (--resume) meanwhile.
func retrySync(ctx context.Context, a *api.API, log *slog.Logger) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c, cancel := context.WithTimeout(ctx, time.Minute)
		err := a.Sync(c)
		cancel()
		if err == nil {
			log.Info("config pushed to engine")
			return
		}
	}
}

// purge drops old requests, events and sessions once an hour.
func purge(ctx context.Context, st *store.Store, cfg config, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		n := time.Now()
		if err := st.Purge(ctx, n.AddDate(0, 0, -cfg.RetentionDays), n.AddDate(0, 0, -cfg.EventRetentionDays), n); err != nil && ctx.Err() == nil {
			log.Error("purge", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
