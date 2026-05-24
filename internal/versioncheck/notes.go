package versioncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/vaultify/vaultify/internal/buildinfo"
)

// ReleaseNoteChange is one bullet on the Version page.
type ReleaseNoteChange struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ReleaseNote is structured release notes for one version.
type ReleaseNote struct {
	Version string              `json:"version"`
	Date    string              `json:"date"`
	Summary string              `json:"summary,omitempty"`
	Changes []ReleaseNoteChange `json:"changes"`
}

// ReleaseNotesResponse is returned by GET /api/version/notes.
type ReleaseNotesResponse struct {
	Current  string        `json:"current"`
	Releases []ReleaseNote `json:"releases"`
	Error    string        `json:"error,omitempty"`
}

func releaseNotesIndexURL() string {
	if testReleaseNotesIndexURL != "" {
		return testReleaseNotesIndexURL
	}
	return "https://raw.githubusercontent.com/" + buildinfo.GitHubRepo + "/main/releases/notes/index.json"
}

func releaseNoteURL(version string) string {
	version = strings.TrimSpace(strings.TrimPrefix(version, "v"))
	if testReleaseNoteURLPrefix != "" {
		return testReleaseNoteURLPrefix + version + ".json"
	}
	return "https://raw.githubusercontent.com/" + buildinfo.GitHubRepo + "/main/releases/notes/" + version + ".json"
}

// Test hooks (notes_test.go).
var (
	testReleaseNotesIndexURL string
	testReleaseNoteURLPrefix string
)

type notesIndex struct {
	Schema   int      `json:"schema"`
	Versions []string `json:"versions"`
}

// FetchReleaseNotes loads the index and each version's notes from GitHub raw content.
func FetchReleaseNotes(ctx context.Context, current string, client *http.Client) ReleaseNotesResponse {
	current = strings.TrimSpace(current)
	res := ReleaseNotesResponse{Current: current}
	if client == nil {
		client = http.DefaultClient
	}

	index, err := fetchNotesIndex(ctx, client)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		first error
	)
	notes := make([]ReleaseNote, len(index.Versions))
	for i, ver := range index.Versions {
		i, ver := i, ver
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := fetchReleaseNote(ctx, client, ver)
			if err != nil {
				mu.Lock()
				if first == nil {
					first = fmt.Errorf("%s: %w", ver, err)
				}
				mu.Unlock()
				return
			}
			notes[i] = n
		}()
	}
	wg.Wait()
	if first != nil {
		res.Error = first.Error()
	}

	out := make([]ReleaseNote, 0, len(notes))
	for _, n := range notes {
		if n.Version != "" && len(n.Changes) > 0 {
			out = append(out, n)
		}
	}
	res.Releases = out
	return res
}

func fetchNotesIndex(ctx context.Context, client *http.Client) (notesIndex, error) {
	body, err := fetchRawJSON(ctx, client, releaseNotesIndexURL())
	if err != nil {
		return notesIndex{}, err
	}
	var idx notesIndex
	if err := json.Unmarshal(body, &idx); err != nil {
		return notesIndex{}, err
	}
	if len(idx.Versions) == 0 {
		return notesIndex{}, fmt.Errorf("release notes index empty")
	}
	return idx, nil
}

func fetchReleaseNote(ctx context.Context, client *http.Client, version string) (ReleaseNote, error) {
	version = strings.TrimSpace(strings.TrimPrefix(version, "v"))
	body, err := fetchRawJSON(ctx, client, releaseNoteURL(version))
	if err != nil {
		return ReleaseNote{}, err
	}
	var n ReleaseNote
	if err := json.Unmarshal(body, &n); err != nil {
		return ReleaseNote{}, err
	}
	if n.Version == "" {
		n.Version = version
	}
	return n, nil
}

func fetchRawJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Vaultify/"+buildinfo.Version())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256*1024))
}

// SummaryForVersion returns the summary line for a version if notes exist locally via fetch.
func SummaryForVersion(ctx context.Context, version string, client *http.Client) string {
	n, err := fetchReleaseNote(ctx, client, version)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(n.Summary)
}
