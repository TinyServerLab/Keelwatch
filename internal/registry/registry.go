// Package registry checks whether a running image is outdated by talking to
// the OCI distribution API anonymously: it compares the remote digest for the
// same tag and looks for newer semver tags.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keelwatch/keelwatch/internal/model"
)

type Ref struct {
	Registry string // host used for API calls
	Repo     string
	Tag      string
	Digest   string
}

// ParseRef normalises references like "nginx", "ghcr.io/a/b:1.2", "x@sha256:..".
func ParseRef(s string) Ref {
	r := Ref{}
	if i := strings.Index(s, "@"); i >= 0 {
		r.Digest = s[i+1:]
		s = s[:i]
	}
	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		r.Registry = parts[0]
		s = parts[1]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i:], "/") {
		r.Tag = s[i+1:]
		s = s[:i]
	}
	r.Repo = s
	if r.Registry == "" || r.Registry == "docker.io" || r.Registry == "index.docker.io" {
		r.Registry = "registry-1.docker.io"
		if !strings.Contains(r.Repo, "/") {
			r.Repo = "library/" + r.Repo
		}
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r
}

type Checker interface {
	Check(ctx context.Context, ref string, localDigests []string) *model.UpdateStatus
}

type HTTPChecker struct {
	Client *http.Client
}

func NewHTTPChecker() *HTTPChecker {
	return &HTTPChecker{Client: &http.Client{Timeout: 20 * time.Second}}
}

const acceptManifests = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"

func (c *HTTPChecker) Check(ctx context.Context, refStr string, localDigests []string) *model.UpdateStatus {
	st := &model.UpdateStatus{Ref: refStr, CheckedAt: time.Now().UTC()}
	ref := ParseRef(refStr)
	if ref.Digest != "" && ref.Tag == "" {
		st.Error = "pinned by digest; tag tracking disabled"
		return st
	}
	if len(localDigests) == 0 {
		st.Error = "no registry digest (locally built image?)"
	}
	tok := ""
	dig, err := c.headDigest(ctx, ref, &tok)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.RemoteDigs = dig
	if len(localDigests) > 0 {
		match := false
		for _, d := range localDigests {
			if i := strings.Index(d, "@"); i >= 0 {
				d = d[i+1:]
			}
			if d == dig {
				match = true
			}
		}
		st.DigestNew = !match
	}
	if cur, ok := parseVersion(ref.Tag); ok {
		tags, err := c.listTags(ctx, ref, &tok)
		if err == nil {
			if best, bump := newestTag(cur, tags); best != "" {
				st.NewestTag, st.Bump = best, bump
			}
		}
	}
	return st
}

func (c *HTTPChecker) do(ctx context.Context, method, u string, ref Ref, tok *string, accept string) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if *tok != "" {
			req.Header.Set("Authorization", "Bearer "+*tok)
		}
		resp, err := c.Client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			ch := resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
			t, err := c.token(ctx, ch, ref)
			if err != nil {
				return nil, err
			}
			*tok = t
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("registry auth failed")
}

func (c *HTTPChecker) headDigest(ctx context.Context, ref Ref, tok *string) (string, error) {
	u := fmt.Sprintf("https://%s/v2/%s/manifests/%s", ref.Registry, ref.Repo, ref.Tag)
	resp, err := c.do(ctx, http.MethodHead, u, ref, tok, acceptManifests)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry returned %s for %s:%s", resp.Status, ref.Repo, ref.Tag)
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if d == "" {
		return "", fmt.Errorf("registry sent no digest")
	}
	return d, nil
}

func (c *HTTPChecker) listTags(ctx context.Context, ref Ref, tok *string) ([]string, error) {
	var all []string
	next := fmt.Sprintf("https://%s/v2/%s/tags/list?n=1000", ref.Registry, ref.Repo)
	for page := 0; page < 8 && next != ""; page++ {
		resp, err := c.do(ctx, http.MethodGet, next, ref, tok, "")
		if err != nil {
			return all, err
		}
		var body struct{ Tags []string }
		err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&body)
		link := resp.Header.Get("Link")
		resp.Body.Close()
		if err != nil {
			return all, err
		}
		all = append(all, body.Tags...)
		next = ""
		if m := linkRe.FindStringSubmatch(link); m != nil {
			base, _ := url.Parse(fmt.Sprintf("https://%s", ref.Registry))
			if nu, err := base.Parse(m[1]); err == nil {
				next = nu.String()
			}
		}
	}
	return all, nil
}

var linkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)
var authParamRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

func (c *HTTPChecker) token(ctx context.Context, challenge string, ref Ref) (string, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer") {
		return "", fmt.Errorf("registry needs credentials")
	}
	params := map[string]string{}
	for _, m := range authParamRe.FindAllStringSubmatch(challenge, -1) {
		params[strings.ToLower(m[1])] = m[2]
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("registry auth challenge has no realm")
	}
	q := url.Values{}
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + ref.Repo + ":pull"
	}
	q.Set("scope", scope)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token: %s (private image?)", resp.Status)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	return body.AccessToken, nil
}

// ---- semver-ish tag comparison ----

type version struct {
	nums   []int
	prefix string // "v" or ""
	suffix string // "-alpine", "-bookworm", ...
	raw    string
}

var verRe = regexp.MustCompile(`^(v?)(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$`)

func parseVersion(tag string) (version, bool) {
	m := verRe.FindStringSubmatch(tag)
	if m == nil {
		return version{}, false
	}
	v := version{prefix: m[1], suffix: m[5], raw: tag}
	for _, s := range m[2:5] {
		if s == "" {
			break
		}
		n, _ := strconv.Atoi(s)
		v.nums = append(v.nums, n)
	}
	// Reject date-like or build-number tags that are not versions.
	if len(v.nums) == 1 && v.nums[0] > 1000 {
		return version{}, false
	}
	return v, true
}

func cmpNums(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// newestTag finds the highest tag with the same shape (prefix, component
// count and suffix) as cur, and classifies the bump.
func newestTag(cur version, tags []string) (string, string) {
	var cands []version
	for _, t := range tags {
		v, ok := parseVersion(t)
		if !ok || v.prefix != cur.prefix || v.suffix != cur.suffix || len(v.nums) != len(cur.nums) {
			continue
		}
		if cmpNums(v.nums, cur.nums) > 0 {
			cands = append(cands, v)
		}
	}
	if len(cands) == 0 {
		return "", ""
	}
	sort.Slice(cands, func(i, j int) bool { return cmpNums(cands[i].nums, cands[j].nums) > 0 })
	best := cands[0]
	bump := "patch"
	switch {
	case best.nums[0] != cur.nums[0]:
		bump = "major"
	case len(best.nums) > 1 && best.nums[1] != cur.nums[1]:
		bump = "minor"
	}
	return best.raw, bump
}
