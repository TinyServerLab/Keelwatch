package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/keelwatch/keelwatch/internal/model"
)

func isComposeFile(name string) bool {
	n := strings.ToLower(name)
	return (strings.HasPrefix(n, "docker-compose") || strings.HasPrefix(n, "compose")) &&
		(strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml"))
}

func isEnvFile(name string) bool {
	n := strings.ToLower(name)
	return n == ".env" || strings.HasSuffix(n, ".env") || strings.HasPrefix(n, ".env.")
}

// ComposeRules scans compose and .env files under the given directories
// (mounted read-only into Keelwatch) for hard-coded and exposed secrets.
func ComposeRules(dirs []string) []model.Finding {
	var out []model.Finding
	for _, root := range dirs {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		baseDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				n := d.Name()
				if n == "node_modules" || n == ".git" || n == "data" || strings.Count(p, string(os.PathSeparator))-baseDepth > 4 {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			compose, env := isComposeFile(name), isEnvFile(name)
			if !compose && !env {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > 1<<20 {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			fb := &fb{tt: model.TargetFile, target: p}
			for _, h := range scanText(string(b)) {
				disc := h.Hit.Key + ":" + strconv.Itoa(h.Line)
				ev := p + ":" + strconv.Itoa(h.Line) + "  " + h.Hit.Key + "=" + h.Hit.Redacted
				switch {
				case compose && (h.Hit.Known || h.Hit.Weak):
					fb.addD("compose-secret", disc, model.CatCredentials, model.SevCritical, "",
						h.Hit.Kind+" hard-coded in compose file",
						"Compose files are often committed to Git and shared. This value is readable by anyone with the file.",
						"Rotate it, then reference it from a `.env` file kept out of Git, or better, a Docker secret (`secrets:` + `<VAR>_FILE`).", ev)
				case compose:
					fb.addD("compose-secret", disc, model.CatCredentials, model.SevHigh, "",
						"Plaintext secret in compose file: "+h.Hit.Key,
						"Secrets written inline in compose files leak through Git, backups and screenshots.",
						"Replace with `${"+h.Hit.Key+"}` and set it in a `.env` file excluded from Git, or use Docker secrets.", ev)
				case env && h.Hit.Weak:
					fb.addD("env-file-weak", disc, model.CatCredentials, model.SevHigh, "",
						"Default/weak credential in "+name+": "+h.Hit.Key,
						"Well-known default values are the first thing attackers try.",
						"Generate a strong value: `openssl rand -base64 32`.", ev)
				}
			}
			if env {
				if info.Mode().Perm()&0o004 != 0 {
					fb.add("env-world-readable", model.CatCredentials, model.SevMedium, "3.x",
						"Secrets file is readable by every user",
						"Any local user or process can read this .env file.",
						"`chmod 600 "+p+"`", info.Mode().Perm().String())
				}
				if inGitRepoUnignored(p) {
					fb.add("env-not-gitignored", model.CatCredentials, model.SevMedium, "",
						".env file is not git-ignored",
						"This file sits in a Git repository whose .gitignore does not exclude it, so it can be committed and pushed.",
						"Add `.env` to .gitignore. If it was ever committed, rotate the secrets and purge them from history.", p)
				}
			}
			out = append(out, fb.out...)
			return nil
		})
	}
	return out
}

func inGitRepoUnignored(p string) bool {
	dir := filepath.Dir(p)
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			gi, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
			if err != nil {
				return true
			}
			for _, l := range strings.Split(string(gi), "\n") {
				l = strings.TrimSpace(l)
				if l == ".env" || l == "*.env" || l == ".env*" || l == "/.env" || l == ".env.*" {
					return false
				}
			}
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}
