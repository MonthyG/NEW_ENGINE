package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"hostinginside/waf/manager/site"
	"hostinginside/waf/manager/store"
)

// --- certificates ----------------------------------------------------------

type globalCertView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	DNSNames []string  `json:"dns_names"`
	NotAfter time.Time `json:"not_after"`
	UsedBy   []string  `json:"used_by"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
}

type certDocReq struct {
	Name    string `json:"name"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func certViewOf(o store.Object, usedBy []string) (globalCertView, error) {
	var c site.Certificate
	if err := json.Unmarshal(o.Doc, &c); err != nil {
		return globalCertView{}, err
	}
	v := globalCertView{ID: o.ID, Name: c.Name, UsedBy: usedBy, Created: o.Created, Updated: o.Updated}
	if v.UsedBy == nil {
		v.UsedBy = []string{}
	}
	if pair, err := parsePair(c.CertPEM, c.KeyPEM); err == nil && pair.Leaf != nil {
		v.Subject, v.Issuer = pair.Leaf.Subject.CommonName, pair.Leaf.Issuer.CommonName
		v.DNSNames, v.NotAfter = pair.Leaf.DNSNames, pair.Leaf.NotAfter.UTC()
	}
	return v, nil
}

// certUsers maps certificate IDs to the sites using them.
func certUsers(recs []store.SiteRecord) map[string][]string {
	out := map[string][]string{}
	for _, r := range recs {
		if r.Doc.TLS != nil && r.Doc.TLS.CertID != "" {
			out[r.Doc.TLS.CertID] = append(out[r.Doc.TLS.CertID], r.ID)
		}
	}
	return out
}

func (a *API) listCerts(w http.ResponseWriter, r *http.Request) {
	objs, err := a.st.ListObjects(r.Context(), store.KindCert)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	recs, err := a.st.ListSites(r.Context())
	if err != nil {
		a.writeErr(w, err)
		return
	}
	users := certUsers(recs)
	out := make([]globalCertView, 0, len(objs))
	for _, o := range objs {
		v, err := certViewOf(o, users[o.ID])
		if err != nil {
			a.writeErr(w, err)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func readCert(w http.ResponseWriter, r *http.Request) (site.Certificate, error) {
	var req certDocReq
	if err := decode(w, r, &req); err != nil {
		return site.Certificate{}, err
	}
	pair, err := parsePair(req.CertPEM, req.KeyPEM)
	if err != nil {
		return site.Certificate{}, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" && pair.Leaf != nil {
		name = pair.Leaf.Subject.CommonName
		if name == "" && len(pair.Leaf.DNSNames) > 0 {
			name = pair.Leaf.DNSNames[0]
		}
	}
	if name == "" || utf8.RuneCountInString(name) > 64 {
		return site.Certificate{}, badRequest("name", "must be 1-64 characters")
	}
	return site.Certificate{Name: name, CertPEM: req.CertPEM, KeyPEM: req.KeyPEM}, nil
}

func (a *API) createCert(w http.ResponseWriter, r *http.Request) {
	c, err := readCert(w, r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	id, t := site.NewObjectID("c"), now()
	if err := a.st.Tx(r.Context(), func(tx *store.Tx) error {
		return tx.PutObject(store.KindCert, id, c, t, t)
	}); err != nil {
		a.writeErr(w, err)
		return
	}
	b, _ := json.Marshal(c)
	v, err := certViewOf(store.Object{Kind: store.KindCert, ID: id, Doc: b, Created: t, Updated: t}, nil)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

// updateCert replaces a certificate; sites using it are reloaded.
func (a *API) updateCert(w http.ResponseWriter, r *http.Request) {
	c, err := readCert(w, r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	id := r.PathValue("id")
	var obj store.Object
	err = a.apply(mutationCtx(r), func(tx *store.Tx) error {
		old, ok, err := tx.GetObject(store.KindCert, id)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		t := now()
		b, _ := json.Marshal(c)
		obj = store.Object{Kind: store.KindCert, ID: id, Doc: b, Created: old.Created, Updated: t}
		return tx.PutObject(store.KindCert, id, c, old.Created, t)
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	v, _ := certViewOf(obj, nil)
	writeJSON(w, http.StatusOK, v)
}

func (a *API) deleteCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.st.Tx(mutationCtx(r), func(tx *store.Tx) error {
		recs, err := tx.ListSites()
		if err != nil {
			return err
		}
		if users := certUsers(recs)[id]; len(users) > 0 {
			return &httpError{status: http.StatusConflict, msg: "certificate is used by site " + users[0]}
		}
		ok, err := tx.DeleteObject(store.KindCert, id)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		return nil
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- IP groups ---------------------------------------------------------------

type groupView struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	site.IPGroup
}

func groupViewOf(o store.Object) (groupView, error) {
	v := groupView{ID: o.ID, Created: o.Created, Updated: o.Updated}
	err := json.Unmarshal(o.Doc, &v.IPGroup)
	if v.IPs == nil {
		v.IPs = []string{}
	}
	return v, err
}

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	objs, err := a.st.ListObjects(r.Context(), store.KindIPGroup)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	out := make([]groupView, 0, len(objs))
	for _, o := range objs {
		v, err := groupViewOf(o)
		if err != nil {
			a.writeErr(w, err)
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func readGroup(w http.ResponseWriter, r *http.Request) (site.IPGroup, error) {
	var g site.IPGroup
	if err := decode(w, r, &g); err != nil {
		return g, err
	}
	g.Name = strings.TrimSpace(g.Name)
	var ips []string
	for _, ip := range g.IPs {
		if ip = strings.TrimSpace(ip); ip != "" {
			ips = append(ips, ip)
		}
	}
	g.IPs = ips
	return g, site.ValidateIPGroup(g)
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	g, err := readGroup(w, r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	id, t := site.NewObjectID("g"), now()
	if err := a.st.Tx(r.Context(), func(tx *store.Tx) error {
		return tx.PutObject(store.KindIPGroup, id, g, t, t)
	}); err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, groupView{ID: id, Created: t, Updated: t, IPGroup: g})
}

func (a *API) updateGroup(w http.ResponseWriter, r *http.Request) {
	g, err := readGroup(w, r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	id := r.PathValue("id")
	var v groupView
	err = a.apply(mutationCtx(r), func(tx *store.Tx) error {
		old, ok, err := tx.GetObject(store.KindIPGroup, id)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		t := now()
		v = groupView{ID: id, Created: old.Created, Updated: t, IPGroup: g}
		return tx.PutObject(store.KindIPGroup, id, g, old.Created, t)
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.st.Tx(mutationCtx(r), func(tx *store.Tx) error {
		recs, err := tx.ListSites()
		if err != nil {
			return err
		}
		docs := map[string]site.Doc{}
		for _, rec := range recs {
			docs[rec.ID] = rec.Doc
		}
		rules, err := listRules(tx)
		if err != nil {
			return err
		}
		if err := site.CheckGroupUnused(id, docs, rules); err != nil {
			return &httpError{status: http.StatusConflict, msg: err.Error()}
		}
		ok, err := tx.DeleteObject(store.KindIPGroup, id)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		return nil
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- global custom rules -------------------------------------------------

type ruleView struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	site.GlobalRule
}

type ruleRec struct {
	site.IDRule
	created, updated time.Time
}

func listRuleRecs(tx *store.Tx) ([]ruleRec, error) {
	objs, err := tx.ListObjects(store.KindRule)
	if err != nil {
		return nil, err
	}
	out := make([]ruleRec, 0, len(objs))
	for _, o := range objs {
		var gr site.GlobalRule
		if err := json.Unmarshal(o.Doc, &gr); err != nil {
			return nil, err
		}
		out = append(out, ruleRec{IDRule: site.IDRule{ID: o.ID, GlobalRule: gr}, created: o.Created, updated: o.Updated})
	}
	// Stable: equal priorities keep creation order.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}

// listRules returns the global rules in evaluation order.
func listRules(tx *store.Tx) ([]site.IDRule, error) {
	recs, err := listRuleRecs(tx)
	if err != nil {
		return nil, err
	}
	out := make([]site.IDRule, len(recs))
	for i, r := range recs {
		out[i] = r.IDRule
	}
	return out, nil
}

func (a *API) listRules(w http.ResponseWriter, r *http.Request) {
	var recs []ruleRec
	if err := a.st.Tx(r.Context(), func(tx *store.Tx) error {
		var err error
		recs, err = listRuleRecs(tx)
		return err
	}); err != nil {
		a.writeErr(w, err)
		return
	}
	out := make([]ruleView, 0, len(recs))
	for _, rr := range recs {
		out = append(out, ruleView{ID: rr.ID, Created: rr.created, Updated: rr.updated, GlobalRule: rr.GlobalRule})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) readRule(w http.ResponseWriter, r *http.Request) (site.GlobalRule, error) {
	var gr site.GlobalRule
	if err := decode(w, r, &gr); err != nil {
		return gr, err
	}
	gr.Name = strings.TrimSpace(gr.Name)
	return gr, site.ValidateGlobalRule(gr, a.opt.GeoIPDB != "")
}

func (a *API) createRule(w http.ResponseWriter, r *http.Request) {
	gr, err := a.readRule(w, r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	id, t := site.NewObjectID("r"), now()
	if err := a.apply(mutationCtx(r), func(tx *store.Tx) error {
		return tx.PutObject(store.KindRule, id, gr, t, t)
	}); err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, ruleView{ID: id, Created: t, Updated: t, GlobalRule: gr})
}

func (a *API) updateRule(w http.ResponseWriter, r *http.Request) {
	gr, err := a.readRule(w, r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	id := r.PathValue("id")
	var v ruleView
	err = a.apply(mutationCtx(r), func(tx *store.Tx) error {
		old, ok, err := tx.GetObject(store.KindRule, id)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		t := now()
		v = ruleView{ID: id, Created: old.Created, Updated: t, GlobalRule: gr}
		return tx.PutObject(store.KindRule, id, gr, old.Created, t)
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.apply(mutationCtx(r), func(tx *store.Tx) error {
		ok, err := tx.DeleteObject(store.KindRule, id)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		return nil
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
