package registry

import "testing"

func TestParseRef(t *testing.T) {
	cases := map[string]Ref{
		"nginx":                           {Registry: "registry-1.docker.io", Repo: "library/nginx", Tag: "latest"},
		"nginx:1.25-alpine":               {Registry: "registry-1.docker.io", Repo: "library/nginx", Tag: "1.25-alpine"},
		"louislam/uptime-kuma:1":          {Registry: "registry-1.docker.io", Repo: "louislam/uptime-kuma", Tag: "1"},
		"ghcr.io/home/app:v2.0.1":         {Registry: "ghcr.io", Repo: "home/app", Tag: "v2.0.1"},
		"localhost:5000/me/app":           {Registry: "localhost:5000", Repo: "me/app", Tag: "latest"},
		"lscr.io/linuxserver/x@sha256:ab": {Registry: "lscr.io", Repo: "linuxserver/x", Digest: "sha256:ab"},
	}
	for in, want := range cases {
		if got := ParseRef(in); got != want {
			t.Errorf("%s: got %+v want %+v", in, got, want)
		}
	}
}

func TestNewestTag(t *testing.T) {
	tags := []string{"1.24.0", "1.25.3", "1.25.4", "1.26.0", "2.0.0-rc1", "1.25.5-alpine", "latest", "1.25", "20240101"}
	cur, _ := parseVersion("1.25.3")
	if best, bump := newestTag(cur, tags); best != "1.26.0" || bump != "minor" {
		t.Errorf("got %s %s", best, bump)
	}
	cur, _ = parseVersion("1.25-alpine")
	if best, _ := newestTag(cur, []string{"1.26-alpine", "1.27", "2.0-alpine"}); best != "2.0-alpine" {
		t.Errorf("suffix match failed: %s", best)
	}
	cur, _ = parseVersion("1.26.0")
	if best, _ := newestTag(cur, tags); best != "" {
		t.Errorf("should be newest already, got %s", best)
	}
	if _, ok := parseVersion("latest"); ok {
		t.Error("latest is not a version")
	}
}
