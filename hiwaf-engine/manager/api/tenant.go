package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"hostinginside/waf/manager/site"
	"hostinginside/waf/manager/store"
)

// ProjectHeader lets an operator key or console session act for one project:
// the OpenStack service checks the customer's Keystone token, then calls the
// manager with its own key and this header. A project token carries its
// project itself and may only repeat it here.
const ProjectHeader = "X-Project-Id"

// scope says what a route lets a project caller do. Routes are admin-only
// unless they say otherwise, so a new route is closed to tenants by default.
type scope int

const (
	adminOnly  scope = iota // operator only: a project caller gets 403
	anyCaller               // open; the handler limits what a project sees
	siteInPath              // the {id} site must belong to the caller's project
	siteParam               // ?site= is required and must belong to the project
	txInPath                // the {tx} event's site must belong to the project
)

// gate enforces s for project callers before h runs. Sites of other projects
// answer 404, as if they did not exist.
func (a *API) gate(s scope, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := principalOf(r)
		if p.Project == "" {
			h(w, r)
			return
		}
		var id string
		switch s {
		case anyCaller:
			h(w, r)
			return
		case siteInPath:
			id = r.PathValue("id")
		case siteParam:
			if id = r.URL.Query().Get("site"); id == "" {
				a.writeErr(w, badRequest("site", "a project caller must name one of its sites"))
				return
			}
		case txInPath:
			id, _, _ = strings.Cut(r.PathValue("tx"), "-") // tx IDs are <site>-<hex>
		default:
			a.writeErr(w, &httpError{status: http.StatusForbidden, msg: "this needs the operator, not a project"})
			return
		}
		ok, err := a.owns(r.Context(), p.Project, id)
		if err != nil {
			a.writeErr(w, err)
			return
		}
		if !ok {
			a.writeErr(w, errNotFound)
			return
		}
		h(w, r)
	}
}

// owns reports whether site id belongs to project.
func (a *API) owns(ctx context.Context, project, id string) (bool, error) {
	var ok bool
	err := a.st.Tx(ctx, func(tx *store.Tx) error {
		rec, found, err := tx.GetSite(id)
		ok = found && rec.Doc.Project == project
		return err
	})
	return ok, err
}

// tenantDoc applies the project rules to a site a project caller writes: it
// belongs to the caller's project whatever the document says, keeps the
// floating IP the operator gave it (prev; nil on create), and must keep to
// the tenant limits.
func tenantDoc(p principal, d *site.Doc, prev *site.Doc) error {
	if p.Project == "" {
		return nil
	}
	d.Project = p.Project
	d.FloatingIP = ""
	if prev != nil {
		d.FloatingIP = prev.FloatingIP
	}
	return site.CheckTenant(*d)
}

// --- domain ownership --------------------------------------------------------

// A project proves a domain is its own with a DNS TXT record before a site of
// it may use the domain; otherwise any customer could claim a domain someone
// else points at the WAF later. The value is an HMAC of project and domain,
// so nothing has to be stored: it is the same every time it is asked for.

// TXTLookup resolves TXT records; net.DefaultResolver.LookupTXT in production.
type TXTLookup func(ctx context.Context, name string) ([]string, error)

// SetDomainCheck turns the ownership check on for project callers; nil turns it off.
func (a *API) SetDomainCheck(l TXTLookup) { a.lookupTXT = l }

var claimDomainRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// claimRecord returns the TXT record name and value that prove project owns
// domain. A wildcard is proven at its base: *.shop.com by _hiwaf.shop.com.
func (a *API) claimRecord(project, domain string) (name, value string) {
	h := hmac.New(sha256.New, []byte(a.opt.ChallengeSecret))
	h.Write([]byte("claim|" + project + "|" + domain))
	return "_hiwaf." + strings.TrimPrefix(domain, "*."), "hiwaf-verify=" + hex.EncodeToString(h.Sum(nil)[:16])
}

// claimed reports whether the TXT record for project and domain is published.
func (a *API) claimed(ctx context.Context, project, domain string) bool {
	name, value := a.claimRecord(project, domain)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	txt, err := a.lookupTXT(ctx, name)
	return err == nil && slices.Contains(txt, value)
}

// checkClaims requires a proof for every domain of d a project caller adds;
// domains the site already had (prev) were proven when they were added.
func (a *API) checkClaims(ctx context.Context, p principal, d site.Doc, prev *site.Doc) error {
	if p.Project == "" || a.lookupTXT == nil {
		return nil
	}
	var had []string
	if prev != nil {
		had = prev.Domains
	}
	for i, dom := range d.Domains {
		dom = strings.ToLower(strings.TrimSpace(dom))
		if slices.ContainsFunc(had, func(h string) bool { return strings.ToLower(strings.TrimSpace(h)) == dom }) {
			continue
		}
		if !a.claimed(ctx, p.Project, dom) {
			name, value := a.claimRecord(p.Project, dom)
			return badRequest(fmt.Sprintf("domains[%d]", i), fmt.Sprintf(
				"prove %s is yours first: add a DNS TXT record %s with the value %s", dom, name, value))
		}
	}
	return nil
}

type domainCheckView struct {
	Domain      string `json:"domain"`
	RecordName  string `json:"record_name"`
	RecordValue string `json:"record_value"`
	Required    bool   `json:"required"` // false for the operator, or with the check off
	Verified    bool   `json:"verified"`
}

// domainCheck tells a project caller which TXT record proves ?domain= and
// whether it is published yet.
func (a *API) domainCheck(w http.ResponseWriter, r *http.Request) {
	dom := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if len(dom) > 253 || !claimDomainRE.MatchString(dom) {
		a.writeErr(w, badRequest("domain", "a domain name such as shop.example.com"))
		return
	}
	p := principalOf(r)
	v := domainCheckView{Domain: dom, Required: p.Project != "" && a.lookupTXT != nil}
	v.RecordName, v.RecordValue = a.claimRecord(p.Project, dom)
	v.Verified = !v.Required || a.claimed(r.Context(), p.Project, dom)
	writeJSON(w, http.StatusOK, v)
}

// hideOthers rewrites a validation error that names another site (a domain
// already taken) so a project caller learns nothing about other projects.
func hideOthers(p principal, err error) error {
	var ve *site.ValidationError
	if p.Project != "" && errors.As(err, &ve) && strings.Contains(ve.Msg, "already used by site") {
		return &site.ValidationError{Field: ve.Field, Msg: "a domain of this site is already used by another site"}
	}
	return err
}
