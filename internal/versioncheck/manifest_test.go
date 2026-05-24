package versioncheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchManifestGitHubAPIFallback(t *testing.T) {
	ResetManifestCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/latest" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name":"v0.3.0","html_url":"https://github.com/securityjoes/vaultify/releases/tag/v0.3.0","published_at":"2026-05-01T12:00:00Z"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	testManifestJSONURL = srv.URL + "/missing/latest.json"
	testReleaseAPIURL = srv.URL + "/releases/latest"
	t.Cleanup(func() {
		testManifestJSONURL = ""
		testReleaseAPIURL = ""
	})

	m, err := FetchManifest(context.Background(), srv.Client())
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if m.Version != "0.3.0" {
		t.Fatalf("version=%q want 0.3.0", m.Version)
	}
}

func TestCheckAheadOfPublished(t *testing.T) {
	ResetManifestCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v0.3.0","html_url":"https://github.com/securityjoes/vaultify/releases/tag/v0.3.0"}`))
	}))
	t.Cleanup(srv.Close)

	testManifestJSONURL = "http://127.0.0.1:1/latest.json"
	testReleaseAPIURL = srv.URL + "/releases/latest"
	t.Cleanup(func() {
		testManifestJSONURL = ""
		testReleaseAPIURL = ""
	})

	res := Check(context.Background(), "0.4.0", srv.Client())
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	if res.UpdateAvailable {
		t.Fatal("expected no update when running ahead of published release")
	}
	if !res.AheadOfPublished {
		t.Fatal("expected ahead_of_published")
	}
	if res.Latest != "0.3.0" {
		t.Fatalf("latest=%q want 0.3.0", res.Latest)
	}
}
