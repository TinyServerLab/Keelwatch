package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

type secretPattern struct {
	Name string
	Re   *regexp.Regexp
}

// Value patterns for well-known credential formats. A match means a real
// credential is almost certainly present.
var secretPatterns = []secretPattern{
	{"AWS access key", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b`)},
	{"GitLab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`)},
	{"Stripe live key", regexp.MustCompile(`\b[rs]k_live_[0-9A-Za-z]{20,}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`)},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(proj-)?[A-Za-z0-9_\-]{32,}\b`)},
	{"Telegram bot token", regexp.MustCompile(`\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b`)},
	{"Discord webhook", regexp.MustCompile(`https://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{30,}`)},
	{"Private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY`)},
	{"JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"Database URL with password", regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:\s/@]+:[^@\s]{3,}@`)},
}

var secretNameRe = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth[_-]?key|client[_-]?secret|encryption[_-]?key|jwt|(^|[_-])key$)`)

// Names that look secret-ish but are configuration knobs, not credentials.
var secretNameAllow = regexp.MustCompile(`(?i)(_FILE$|_PATH$|_URL$|_HOST$|_PORT$|_USER(NAME)?$|_ENABLED?$|_LENGTH$|_TTL$|_EXPIR|_TIMEOUT$|_ALGORITHM$|_ISSUER$|_TYPE$|_MODE$|^PASSWORD_HASH|PUBLIC|_ID$)`)

var weakValues = map[string]bool{
	"password": true, "changeme": true, "change_me": true, "admin": true, "secret": true,
	"123456": true, "12345678": true, "root": true, "toor": true, "pass": true, "test": true,
	"default": true, "letmein": true, "qwerty": true, "postgres": true, "example": true,
}

// Redact shows enough to recognise a value without disclosing it.
func Redact(v string) string {
	h := sha256.Sum256([]byte(v))
	shown := ""
	if len(v) >= 12 {
		shown = v[:4]
	}
	return fmt.Sprintf("%s… (%d chars, sha256:%s)", shown, len(v), hex.EncodeToString(h[:4]))
}

type secretHit struct {
	Key      string
	Kind     string // pattern name, "plaintext secret" or "weak default"
	Known    bool   // matched a well-known credential format
	Weak     bool
	Redacted string
}

// classifyKV inspects one KEY=VALUE pair.
func classifyKV(key, val string) *secretHit {
	val = strings.TrimSpace(strings.Trim(val, `"'`))
	if val == "" {
		return nil
	}
	for _, p := range secretPatterns {
		if p.Re.MatchString(val) {
			return &secretHit{Key: key, Kind: p.Name, Known: true, Redacted: Redact(val)}
		}
	}
	if !secretNameRe.MatchString(key) || secretNameAllow.MatchString(key) {
		return nil
	}
	if strings.HasPrefix(val, "/run/secrets/") || strings.HasPrefix(val, "${") || strings.HasPrefix(val, "$(") {
		return nil
	}
	if b := strings.ToLower(val); b == "true" || b == "false" || b == "none" || b == "null" {
		return nil
	}
	if weakValues[strings.ToLower(val)] {
		return &secretHit{Key: key, Kind: "weak default credential", Weak: true, Redacted: Redact(val)}
	}
	if len(val) < 6 {
		return nil
	}
	return &secretHit{Key: key, Kind: "plaintext secret", Redacted: Redact(val)}
}

// scanEnv checks container/image environment variables.
func scanEnv(env []string) []secretHit {
	var out []secretHit
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if h := classifyKV(k, v); h != nil {
			out = append(out, *h)
		}
	}
	return out
}

var kvLineRe = regexp.MustCompile(`^\s*-?\s*["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*(.+?)\s*$`)

// scanText checks a compose/.env file line by line.
func scanText(content string) []struct {
	Line int
	Hit  secretHit
} {
	var out []struct {
		Line int
		Hit  secretHit
	}
	for i, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		var hit *secretHit
		if m := kvLineRe.FindStringSubmatch(t); m != nil {
			hit = classifyKV(m[1], m[2])
		} else {
			for _, p := range secretPatterns {
				if p.Re.MatchString(t) {
					hit = &secretHit{Key: "(inline)", Kind: p.Name, Known: true, Redacted: Redact(p.Re.FindString(t))}
					break
				}
			}
		}
		if hit != nil {
			out = append(out, struct {
				Line int
				Hit  secretHit
			}{i + 1, *hit})
		}
	}
	return out
}
