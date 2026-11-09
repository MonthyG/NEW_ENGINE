package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"hostinginside/waf/manager/caddyclient"
	"hostinginside/waf/manager/compile"
	"hostinginside/waf/manager/store"
)

const testKey = "test-key"

// fakeLoader records every loaded config and fails with err when set.
type fakeLoader struct {
	mu      sync.Mutex
	configs []any
	err     error
}

func (f *fakeLoader) Load(_ context.Context, cfg any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.configs = append(f.configs, cfg)
	return nil
}

func (f *fakeLoader) Bans(context.Context, string) (map[string][]caddyclient.Ban, error) {
	return nil, f.err
}

func (f *fakeLoader) Unban(context.Context, string, string) (bool, error) { return true, f.err }

func (f *fakeLoader) WaitRooms(context.Context) (map[string]caddyclient.WaitRoom, error) {
	return map[string]caddyclient.WaitRoom{}, f.err
}

func (f *fakeLoader) loads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.configs)
}

func newTestAPI(t *testing.T, setup ...func(*API)) (http.Handler, *fakeLoader) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "waf.db"))
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })
	fl := &fakeLoader{}
	opt := compile.Options{
		AdminListen:     "127.0.0.1:2019",
		HTTPPort:        80,
		HTTPSPort:       443,
		EventLog:        "events.log",
		ChallengeSecret: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	a := New(st, fl, opt, []string{testKey})
	for _, f := range setup {
		f(a)
	}
	return a.Handler(), fl
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doKey(t, h, method, path, body, "Bearer "+testKey)
}

func doKey(t *testing.T, h http.Handler, method, path, body, authz string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), v), rec.Body.String())
}

func listLen(t *testing.T, h http.Handler) int {
	t.Helper()
	rec := do(t, h, "GET", "/api/v1/sites", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list []map[string]any
	decodeBody(t, rec, &list)
	return len(list)
}

const minimalDoc = `{"domains":["shop.example.com"],"upstreams":["10.0.0.5:8080"]}`

func createSite(t *testing.T, h http.Handler, doc string) string {
	t.Helper()
	rec := do(t, h, "POST", "/api/v1/sites", doc)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var v struct{ ID string }
	decodeBody(t, rec, &v)
	require.NotEmpty(t, v.ID)
	return v.ID
}

func TestAuthRequired(t *testing.T) {
	h, _ := newTestAPI(t)
	for _, authz := range []string{"", "Bearer wrong", "Bearer ", testKey, "Basic " + testKey} {
		rec := doKey(t, h, "GET", "/api/v1/sites", "", authz)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "authz %q", authz)
	}
	// Unknown routes are also behind auth.
	assert.Equal(t, http.StatusUnauthorized, doKey(t, h, "GET", "/nope", "", "").Code)
	assert.Equal(t, http.StatusOK, do(t, h, "GET", "/api/v1/protections", "").Code)
}

func TestCreateSiteAppliesAndPersists(t *testing.T) {
	h, fl := newTestAPI(t)
	createSite(t, h, minimalDoc)
	require.Equal(t, 1, fl.loads())
	b, err := json.Marshal(fl.configs[0])
	require.NoError(t, err)
	assert.Contains(t, string(b), `"shop.example.com"`)
	assert.Equal(t, 1, listLen(t, h))
}

func TestRollbackWhenCaddyRejects(t *testing.T) {
	h, fl := newTestAPI(t)
	fl.err = &caddyclient.LoadError{Status: 400, Body: "bad"}
	rec := do(t, h, "POST", "/api/v1/sites", minimalDoc)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Contains(t, rec.Body.String(), "bad")
	assert.Equal(t, 0, listLen(t, h))
}

func TestUnreachableIs503(t *testing.T) {
	h, fl := newTestAPI(t)
	fl.err = fmt.Errorf("%w", caddyclient.ErrUnreachable)
	rec := do(t, h, "POST", "/api/v1/sites", minimalDoc)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, 0, listLen(t, h))
}

// A load the engine didn't answer may still be applied, so the saved config
// is pushed again once the engine is back.
func TestUnansweredLoadIsResynced(t *testing.T) {
	h, fl := newTestAPI(t, func(a *API) { a.resyncRetry = 10 * time.Millisecond })
	fl.mu.Lock()
	fl.err = fmt.Errorf("%w", caddyclient.ErrUnreachable)
	fl.mu.Unlock()
	assert.Equal(t, http.StatusServiceUnavailable, do(t, h, "POST", "/api/v1/sites", minimalDoc).Code)
	before := fl.loads()
	fl.mu.Lock()
	fl.err = nil
	fl.mu.Unlock()
	assert.Eventually(t, func() bool { return fl.loads() > before }, 2*time.Second, 10*time.Millisecond)
	assert.Equal(t, 0, listLen(t, h), "the rolled-back site stays out")
}

func TestValidationErrorHasField(t *testing.T) {
	h, fl := newTestAPI(t)
	rec := do(t, h, "POST", "/api/v1/sites",
		`{"domains":["shop.example.com"],"upstreams":["10.0.0.5:8080"],"waf":{"paranoia":9}}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var e struct{ Error, Field string }
	decodeBody(t, rec, &e)
	assert.Equal(t, "waf.paranoia", e.Field)
	assert.NotEmpty(t, e.Error)
	assert.Equal(t, 0, fl.loads())
}

func TestUnknownFieldRejected(t *testing.T) {
	h, fl := newTestAPI(t)
	rec := do(t, h, "POST", "/api/v1/sites",
		`{"domains":["shop.example.com"],"upstreams":["10.0.0.5:8080"],"wafx":{}}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, 0, fl.loads())
}

func TestDuplicateDomainRejected(t *testing.T) {
	h, _ := newTestAPI(t)
	createSite(t, h, minimalDoc)
	rec := do(t, h, "POST", "/api/v1/sites", `{"domains":["SHOP.example.com"],"upstreams":["10.0.0.6:80"]}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var e struct{ Field string }
	decodeBody(t, rec, &e)
	assert.Equal(t, "domains", e.Field)
	assert.Equal(t, 1, listLen(t, h))
}

func TestGetShowsResolvedDefaults(t *testing.T) {
	h, _ := newTestAPI(t)
	id := createSite(t, h, minimalDoc)
	rec := do(t, h, "GET", "/api/v1/sites/"+id, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var v struct {
		ID       string                     `json:"id"`
		Doc      map[string]json.RawMessage `json:"doc"`
		Resolved struct {
			RateLimit map[string]json.RawMessage `json:"rate_limit"`
		} `json:"resolved"`
	}
	decodeBody(t, rec, &v)
	assert.Equal(t, id, v.ID)
	_, hasRL := v.Doc["rate_limit"]
	assert.False(t, hasRL, "doc is the stored doc, not the resolved one")
	assert.JSONEq(t, `{"requests":10,"window_sec":60,"ban_sec":1800}`, string(v.Resolved.RateLimit["attack"]))
	access, ok := v.Resolved.RateLimit["access"]
	require.True(t, ok, "access key present")
	assert.Equal(t, "null", string(access))

	assert.Equal(t, http.StatusNotFound, do(t, h, "GET", "/api/v1/sites/s_000000000000", "").Code)
}

func TestPutKeepsCreatedAndDeleteApplies(t *testing.T) {
	h, fl := newTestAPI(t)
	id := createSite(t, h, minimalDoc)
	var before struct{ Created time.Time }
	decodeBody(t, do(t, h, "GET", "/api/v1/sites/"+id, ""), &before)

	rec := do(t, h, "PUT", "/api/v1/sites/"+id, `{"domains":["new.example.com"],"upstreams":["10.0.0.5:8080"]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var after struct{ Created time.Time }
	decodeBody(t, do(t, h, "GET", "/api/v1/sites/"+id, ""), &after)
	assert.True(t, before.Created.Equal(after.Created))
	assert.Equal(t, 2, fl.loads())

	assert.Equal(t, http.StatusNoContent, do(t, h, "DELETE", "/api/v1/sites/"+id, "").Code)
	assert.Equal(t, 3, fl.loads())
	assert.Equal(t, 0, listLen(t, h))
	assert.Equal(t, http.StatusNotFound, do(t, h, "DELETE", "/api/v1/sites/"+id, "").Code)
}

// selfSigned returns a cert PEM for key k1 and the PEM of key k2.
func selfSigned(t *testing.T, sameKey bool) (certPEM, keyPEM string) {
	t.Helper()
	k1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k2 := k1
	if !sameKey {
		k2, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "shop.example.com"},
		DNSNames:     []string{"shop.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k1.PublicKey, k1)
	require.NoError(t, err)
	kder, err := x509.MarshalECPrivateKey(k2)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}

func certBody(t *testing.T, c, k string) string {
	b, err := json.Marshal(map[string]string{"cert_pem": c, "key_pem": k})
	require.NoError(t, err)
	return string(b)
}

func TestCertUploadRejectsMismatch(t *testing.T) {
	h, fl := newTestAPI(t)
	id := createSite(t, h, minimalDoc)
	c, k := selfSigned(t, false)
	rec := do(t, h, "POST", "/api/v1/sites/"+id+"/certificate", certBody(t, c, k))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, 1, fl.loads())
}

func TestCertUploadNeverEchoesKey(t *testing.T) {
	h, fl := newTestAPI(t)
	id := createSite(t, h, minimalDoc)
	c, k := selfSigned(t, true)
	rec := do(t, h, "POST", "/api/v1/sites/"+id+"/certificate", certBody(t, c, k))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "PRIVATE KEY")
	assert.Contains(t, rec.Body.String(), "shop.example.com")
	assert.Equal(t, 2, fl.loads())
}

// A failed bans call is an engine error, not a rejected config.
func TestBansEngineErrorWording(t *testing.T) {
	h, fl := newTestAPI(t)
	fl.err = &caddyclient.LoadError{Status: 500, Body: `{"error":"boom"}`}
	for _, req := range [][2]string{
		{"GET", "/api/v1/bans?site=s_aaaaaaaaaaaa"},
		{"DELETE", "/api/v1/bans?site=s_aaaaaaaaaaaa&ip=1.2.3.4"},
	} {
		rec := do(t, h, req[0], req[1], "")
		assert.Equal(t, http.StatusBadGateway, rec.Code, req[1])
		var e struct{ Error string }
		decodeBody(t, rec, &e)
		assert.Equal(t, "engine error: boom", e.Error, req[1])
	}
}

func TestAddExclusion(t *testing.T) {
	h, fl := newTestAPI(t)
	id := createSite(t, h, minimalDoc)
	path := "/api/v1/sites/" + id + "/exclusions"
	ex := `{"rule_id":942100,"path_exact":"/search","field":"ARGS:q","note":" null and void "}`
	rec := do(t, h, "POST", path, ex)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var v siteView
	decodeBody(t, rec, &v)
	require.Len(t, v.Resolved.Exclusions, 1)
	assert.Equal(t, "null and void", v.Resolved.Exclusions[0].Note)
	b, _ := json.Marshal(fl.configs[len(fl.configs)-1])
	assert.Contains(t, string(b), "ctl:ruleRemoveTargetById=942100;ARGS:q")

	decodeBody(t, do(t, h, "POST", path, ex), &v)
	assert.Len(t, v.Resolved.Exclusions, 1, "the same exception again changes nothing")
	assert.Equal(t, http.StatusBadRequest, do(t, h, "POST", path, `{"rule_id":949110}`).Code)
	assert.Equal(t, http.StatusBadRequest, do(t, h, "POST", path, `{"rule_id":942100,"field":"ARGS:q,ctl:ruleEngine=Off"}`).Code)
	assert.Equal(t, http.StatusNotFound, do(t, h, "POST", "/api/v1/sites/s_000000000000/exclusions", `{"rule_id":942100}`).Code)

	// the inspection editor's PATCH of waf leaves exceptions alone
	rec = do(t, h, "PATCH", "/api/v1/sites/"+id, `{"waf":{"paranoia":2}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	decodeBody(t, rec, &v)
	assert.Len(t, v.Resolved.Exclusions, 1)
	decodeBody(t, do(t, h, "PATCH", "/api/v1/sites/"+id, `{"exclusions":[]}`), &v)
	assert.Empty(t, v.Resolved.Exclusions)
}
