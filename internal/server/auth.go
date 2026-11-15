package server

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keelwatch/keelwatch/internal/store"
)

const (
	cookieName = "kw_session"
	sessionTTL = 7 * 24 * time.Hour
	pbkdfIter  = 210_000
)

type auth struct {
	disabled bool
	secret   []byte
	hash     []byte
	salt     []byte
	mu       sync.Mutex
	fails    map[string][]time.Time
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randPassword() string {
	const alpha = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alpha[int(b[i])%len(alpha)]
	}
	return string(b)
}

func derive(pw string, salt []byte) []byte {
	k, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	return k
}

// initAuth loads or creates credentials. It returns a freshly generated
// password (to be logged once) when none was configured.
func initAuth(st *store.Store, envPassword string, disabled bool) (*auth, string, error) {
	a := &auth{disabled: disabled, fails: map[string][]time.Time{}}
	generated := ""
	err := st.Update(func(s *store.State) {
		if s.AuthSecret == "" {
			s.AuthSecret = randHex(32)
		}
		switch {
		case envPassword != "":
			salt, _ := hex.DecodeString(s.PassSalt)
			if s.PassHash == "" || hex.EncodeToString(derive(envPassword, salt)) != s.PassHash {
				s.PassSalt = randHex(16)
				salt, _ = hex.DecodeString(s.PassSalt)
				s.PassHash = hex.EncodeToString(derive(envPassword, salt))
				s.AuthSecret = randHex(32) // password changed: invalidate sessions
			}
		case s.PassHash == "" && !disabled:
			generated = randPassword()
			s.PassSalt = randHex(16)
			salt, _ := hex.DecodeString(s.PassSalt)
			s.PassHash = hex.EncodeToString(derive(generated, salt))
		}
		a.secret, _ = hex.DecodeString(s.AuthSecret)
		a.hash, _ = hex.DecodeString(s.PassHash)
		a.salt, _ = hex.DecodeString(s.PassSalt)
	})
	return a, generated, err
}

func (a *auth) sign(exp int64) string {
	m := hmac.New(sha256.New, a.secret)
	fmt.Fprintf(m, "%d", exp)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *auth) issue(w http.ResponseWriter, r *http.Request) {
	exp := time.Now().Add(sessionTTL).Unix()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: strconv.FormatInt(exp, 10) + "." + a.sign(exp), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r), MaxAge: int(sessionTTL.Seconds()),
	})
}

func (a *auth) valid(r *http.Request) bool {
	if a.disabled {
		return true
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	expS, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expS, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(a.sign(exp)))
}

func (a *auth) check(pw string) bool {
	return subtle.ConstantTimeCompare(derive(pw, a.salt), a.hash) == 1
}

// allow implements a simple per-IP lockout: 10 failures per 15 minutes.
func (a *auth) allow(ip string, failed bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	var keep []time.Time
	for _, t := range a.fails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if failed {
		keep = append(keep, time.Now())
	}
	a.fails[ip] = keep
	return len(keep) < 10
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
