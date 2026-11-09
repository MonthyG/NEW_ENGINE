package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// tokenTTL is how long an issued challenge token stays valid.
const tokenTTL = 120 * time.Second

var b64 = base64.RawURLEncoding

// mac computes HMAC-SHA256 over the "|"-joined parts. The first part is a
// domain separator so a challenge token can never be replayed as a clearance
// cookie (or vice versa).
func mac(key []byte, parts ...string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strings.Join(parts, "|")))
	return h.Sum(nil)
}

// issueToken returns b64url(siteID|exp|rand).b64url(HMAC(siteID|ip|exp|rand)).
// The IP is bound by the MAC but not revealed in the payload.
func issueToken(key []byte, siteID, ip string, now time.Time) string {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:]) // crypto/rand.Read never fails (Go 1.24+)
	r := hex.EncodeToString(rnd[:])
	exp := strconv.FormatInt(now.Add(tokenTTL).Unix(), 10)
	payload := siteID + "|" + exp + "|" + r
	return b64.EncodeToString([]byte(payload)) + "." +
		b64.EncodeToString(mac(key, "tok", siteID, ip, exp, r))
}

// checkToken verifies tok was issued for siteID and ip and has not expired.
func checkToken(key []byte, tok, siteID, ip string, now time.Time) error {
	p, m, ok := strings.Cut(tok, ".")
	if !ok {
		return errors.New("malformed token")
	}
	raw, err := b64.DecodeString(p)
	if err != nil {
		return errors.New("malformed token")
	}
	got, err := b64.DecodeString(m)
	if err != nil {
		return errors.New("malformed token")
	}
	f := strings.Split(string(raw), "|")
	if len(f) != 3 || f[0] != siteID {
		return errors.New("token for another site")
	}
	if !hmac.Equal(got, mac(key, "tok", siteID, ip, f[1], f[2])) {
		return errors.New("bad token signature")
	}
	exp, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || !now.Before(time.Unix(exp, 0)) {
		return errors.New("token expired")
	}
	return nil
}

// validPoW reports whether hex(sha256(tok+":"+nonce)) starts with difficulty
// '0' characters.
func validPoW(tok, nonce string, difficulty int) bool {
	sum := sha256.Sum256([]byte(tok + ":" + nonce))
	h := hex.EncodeToString(sum[:])
	if difficulty < 0 || difficulty > len(h) {
		return false
	}
	return strings.Count(h[:difficulty], "0") == difficulty
}

// makeClearance returns "<unix exp>.<b64url HMAC(siteID|ip|exp)>".
func makeClearance(key []byte, siteID, ip string, exp time.Time) string {
	e := strconv.FormatInt(exp.Unix(), 10)
	return e + "." + b64.EncodeToString(mac(key, "clr", siteID, ip, e))
}

// checkClearance verifies a clearance cookie value for siteID and ip.
func checkClearance(key []byte, v, siteID, ip string, now time.Time) bool {
	e, m, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	got, err := b64.DecodeString(m)
	if err != nil {
		return false
	}
	if !hmac.Equal(got, mac(key, "clr", siteID, ip, e)) {
		return false
	}
	exp, err := strconv.ParseInt(e, 10, 64)
	return err == nil && now.Before(time.Unix(exp, 0))
}

// safeReturn returns p if it is a same-site absolute path, otherwise "/".
// It blocks open redirects such as "//host", "/\host" and absolute URLs.
func safeReturn(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n\t") {
		return "/"
	}
	return p
}
