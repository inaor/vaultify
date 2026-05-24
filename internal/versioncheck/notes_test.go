package versioncheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchReleaseNotes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/index.json":
			_, _ = w.Write([]byte(`{"schema":1,"versions":["0.4.0"]}`))
		case "/0.4.0.json":
			_, _ = w.Write([]byte(`{"version":"0.4.0","date":"May 2026","summary":"Test summary","changes":[{"type":"new","text":"Feature A"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	testReleaseNotesIndexURL = srv.URL + "/index.json"
	testReleaseNoteURLPrefix = srv.URL + "/"
	t.Cleanup(func() {
		testReleaseNotesIndexURL = ""
		testReleaseNoteURLPrefix = ""
	})

	res := FetchReleaseNotes(context.Background(), "0.4.0", srv.Client())
	if res.Error != "" {
		t.Fatalf("error: %s", res.Error)
	}
	if len(res.Releases) != 1 {
		t.Fatalf("releases=%d want 1", len(res.Releases))
	}
	if res.Releases[0].Summary != "Test summary" {
		t.Fatalf("summary=%q", res.Releases[0].Summary)
	}
}
