package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPCheckerTokenFlowAndPaging(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") != "repository:me/app:pull" {
				t.Errorf("bad scope %q", r.URL.RawQuery)
			}
			w.Write([]byte(`{"token":"t0k"}`))
			return
		case r.Header.Get("Authorization") != "Bearer t0k":
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+ts.URL+`/token",service="reg",scope="repository:me/app:pull"`)
			w.WriteHeader(401)
			return
		case r.URL.Path == "/v2/me/app/manifests/1.2.3" && r.Method == http.MethodHead:
			if !strings.Contains(r.Header.Get("Accept"), "image.index") {
				t.Error("missing index accept header")
			}
			w.Header().Set("Docker-Content-Digest", "sha256:new")
		case r.URL.Path == "/v2/me/app/tags/list" && r.URL.Query().Get("last") == "":
			w.Header().Set("Link", `</v2/me/app/tags/list?n=1000&last=1.2.4>; rel="next"`)
			w.Write([]byte(`{"tags":["1.2.3","1.2.4"]}`))
		case r.URL.Path == "/v2/me/app/tags/list":
			w.Write([]byte(`{"tags":["1.3.0","latest","2.0.0-beta"]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "https://")
	c := &HTTPChecker{Client: ts.Client()}
	st := c.Check(context.Background(), host+"/me/app:1.2.3", []string{host + "/me/app@sha256:old"})
	if st.Error != "" {
		t.Fatal(st.Error)
	}
	if !st.DigestNew || st.NewestTag != "1.3.0" || st.Bump != "minor" {
		t.Fatalf("unexpected status %+v", st)
	}
	st = c.Check(context.Background(), host+"/me/app:1.2.3", []string{host + "/me/app@sha256:new"})
	if st.DigestNew {
		t.Fatal("matching digest reported as new")
	}
}
