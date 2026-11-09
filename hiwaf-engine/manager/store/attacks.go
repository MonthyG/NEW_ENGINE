package store

import (
	"context"
	"strings"
	"time"
)

// Attack is one WAF transaction worth showing in the attack log: it was
// blocked, or it matched at least one critical (or worse) rule.
type Attack struct {
	TxID                      string
	TS                        time.Time
	SiteID, ClientIP, Country string
	Categories                []string
	Matches, Severity         int
	RuleID, Msg, Data         string // the most severe match
	Blocked                   bool
	Method, Host, URI         string
	Status                    int
}

// AttackFilter narrows the attack log.
type AttackFilter struct {
	SiteID, IP, Category string
	Since, Until         time.Time
	Limit, Offset        int
}

// attackCTE selects qualifying transactions as "q"; the args it needs follow
// the filter's.
func (f AttackFilter) cte() (string, []any) {
	clause, args := " WHERE type = 'waf_match' AND tx_id <> '' AND category <> 'score'", []any{}
	if f.SiteID != "" {
		clause += " AND site_id = ?"
		args = append(args, f.SiteID)
	}
	if f.IP != "" {
		clause += " AND client_ip = ?"
		args = append(args, f.IP)
	}
	if !f.Since.IsZero() {
		clause += " AND ts >= ?"
		args = append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		clause += " AND ts < ?"
		args = append(args, f.Until.UnixMilli())
	}
	having := ` HAVING (MIN(severity) <= 2 OR tx_id IN (SELECT tx_id FROM events WHERE type = 'waf_block' AND tx_id <> ''))`
	if f.Category != "" {
		having += ` AND ',' || GROUP_CONCAT(DISTINCT category) || ',' LIKE ?`
		args = append(args, "%,"+f.Category+",%")
	}
	return `WITH q AS (SELECT tx_id, MIN(ts) AS ts, site_id, client_ip, COUNT(*) AS n, MIN(severity) AS sev,
		GROUP_CONCAT(DISTINCT category) AS cats, MAX(country) AS country FROM events` + clause + ` GROUP BY tx_id` + having + `) `, args
}

func limits(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	return limit, max(offset, 0)
}

// Attacks returns a page of the attack log, newest first, and the total.
func (s *Store) Attacks(ctx context.Context, f AttackFilter) ([]Attack, int, error) {
	cte, args := f.cte()
	var total int
	if err := s.db.QueryRowContext(ctx, cte+`SELECT COUNT(*) FROM q`, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := limits(f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, cte+`SELECT q.tx_id, q.ts, q.site_id, q.client_ip, q.n, q.sev, COALESCE(q.cats, ''),
		COALESCE(m.rule_id, ''), COALESCE(m.msg, ''), COALESCE(m.data, ''), COALESCE(m.uri, ''),
		COALESCE(r.method, ''), COALESCE(r.host, ''), COALESCE(r.uri, ''), COALESCE(r.status, 0),
		COALESCE(r.country, ''), COALESCE(r.action, ''),
		EXISTS(SELECT 1 FROM events b WHERE b.type = 'waf_block' AND b.tx_id = q.tx_id)
		FROM q
		LEFT JOIN events m ON m.id = (SELECT id FROM events e WHERE e.tx_id = q.tx_id AND e.type = 'waf_match'
			AND e.category <> 'score' ORDER BY e.severity, e.id LIMIT 1)
		LEFT JOIN requests r ON r.id = (SELECT id FROM requests x WHERE x.tx_id = q.tx_id LIMIT 1)
		ORDER BY q.ts DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Attack
	for rows.Next() {
		var a Attack
		var ts int64
		var cats, evURI, action string
		var blockEvent bool
		if err := rows.Scan(&a.TxID, &ts, &a.SiteID, &a.ClientIP, &a.Matches, &a.Severity, &cats,
			&a.RuleID, &a.Msg, &a.Data, &evURI, &a.Method, &a.Host, &a.URI, &a.Status, &a.Country,
			&action, &blockEvent); err != nil {
			return nil, 0, err
		}
		a.TS = time.UnixMilli(ts).UTC()
		if cats != "" {
			a.Categories = strings.Split(cats, ",")
		}
		if a.URI == "" {
			a.URI = evURI
		}
		a.Blocked = blockEvent || action == "block"
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// Group is a client IP's activity on one site.
type Group struct {
	SiteID, ClientIP, Country string
	Count                     int
	First, Last               time.Time
}

func scanGroups(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]Group, error) {
	var out []Group
	for rows.Next() {
		var g Group
		var first, last int64
		if err := rows.Scan(&g.SiteID, &g.ClientIP, &g.Country, &g.Count, &first, &last); err != nil {
			return nil, err
		}
		g.First, g.Last = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		out = append(out, g)
	}
	return out, rows.Err()
}

// AttackGroups groups the attack log by site and client IP, most recent first.
func (s *Store) AttackGroups(ctx context.Context, f AttackFilter) ([]Group, int, error) {
	cte, args := f.cte()
	var total int
	if err := s.db.QueryRowContext(ctx, cte+`SELECT COUNT(*) FROM (SELECT 1 FROM q GROUP BY site_id, client_ip)`,
		args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := limits(f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, cte+`SELECT site_id, client_ip, COALESCE(MAX(country), ''), COUNT(*), MIN(ts), MAX(ts) FROM q
		GROUP BY site_id, client_ip ORDER BY MAX(ts) DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out, err := scanGroups(rows)
	return out, total, err
}

// EventGroups groups events matching f by site and client IP.
func (s *Store) EventGroups(ctx context.Context, f EventFilter) ([]Group, int, error) {
	clause, args := f.where()
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM events`+clause+
		` GROUP BY site_id, client_ip)`, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := limits(f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, `SELECT site_id, client_ip, COALESCE(MAX(country), ''), COUNT(*), MIN(ts), MAX(ts) FROM events`+clause+
		` GROUP BY site_id, client_ip ORDER BY MAX(ts) DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out, err := scanGroups(rows)
	return out, total, err
}

// CountEvents counts events matching f (Limit and Offset are ignored).
func (s *Store) CountEvents(ctx context.Context, f EventFilter) (int, error) {
	clause, args := f.where()
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`+clause, args...).Scan(&n)
	return n, err
}

// AttackCounts returns attack-log transaction counts per category since a time.
func (s *Store) AttackCounts(ctx context.Context, siteID string, since time.Time) ([]Count, error) {
	cte, args := AttackFilter{SiteID: siteID, Since: since}.cte()
	rows, err := s.db.QueryContext(ctx, cte+`SELECT e.category, COUNT(DISTINCT e.tx_id) AS n FROM events e
		JOIN q ON q.tx_id = e.tx_id WHERE e.type = 'waf_match' AND e.category NOT IN ('score', '')
		GROUP BY e.category ORDER BY n DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RuleHit is one rule's match count, with the rule's message. Stopped counts
// the matches whose request was stopped; the rest were only watched.
type RuleHit struct {
	RuleID, Msg, Category string
	N, Stopped            int
}

// RuleHits returns the rules that matched most since a time (zero = all), for
// one site or all sites when siteID is empty. Anomaly-score rules are left out.
func (s *Store) RuleHits(ctx context.Context, siteID string, since time.Time, limit int) ([]RuleHit, error) {
	clause, args := where(siteID, "waf_match", "", since)
	rows, err := s.db.QueryContext(ctx, `SELECT rule_id, MAX(msg), MAX(category), COUNT(*) AS n,
		COALESCE(SUM(tx_id <> '' AND (EXISTS(SELECT 1 FROM events b WHERE b.type = 'waf_block' AND b.tx_id = e.tx_id)
			OR EXISTS(SELECT 1 FROM requests x WHERE x.tx_id = e.tx_id AND x.action = 'block'))), 0)
		FROM events e`+clause+` AND rule_id <> '' AND category <> 'score'
		GROUP BY rule_id ORDER BY n DESC, rule_id ASC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleHit
	for rows.Next() {
		var h RuleHit
		if err := rows.Scan(&h.RuleID, &h.Msg, &h.Category, &h.N, &h.Stopped); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
