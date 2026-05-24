package versioncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vaultify/vaultify/internal/buildinfo"
)

const manifestFetchTimeout = 8 * time.Second

// Manifest is releases/latest.json on the repo default branch, or GitHub Releases API fallback.
type Manifest struct {
	Schema           int    `json:"schema"`
	Version          string `json:"version"`
	ReleasedAt       string `json:"released_at"`
	ReleaseURL       string `json:"release_url"`
	DownloadURL      string `json:"download_url"`
	InstallScriptURL string `json:"install_script_url"`
	NotesURL         string `json:"notes_url"`
	Source           string `json:"-"`
}

// CheckResult is returned to the UI via /api/version/check.
type CheckResult struct {
	Current            string `json:"current"`
	Latest             string `json:"latest"`
	LatestPublished    string `json:"latest_published,omitempty"`
	UpdateAvailable    bool   `json:"update_available"`
	AheadOfPublished   bool   `json:"ahead_of_published,omitempty"`
	ReleaseURL         string `json:"release_url,omitempty"`
	DownloadURL        string `json:"download_url,omitempty"`
	ReleasedAt         string `json:"released_at,omitempty"`
	CheckedAt          string `json:"checked_at"`
	Source             string `json:"source,omitempty"`
	Repo               string `json:"repo,omitempty"`
	Error              string `json:"error,omitempty"`
}

type cachedManifest struct {
	at       time.Time
	manifest Manifest
	err      error
}

var (
	cacheMu  sync.Mutex
	cache    cachedManifest
	cacheTTL = 5 * time.Minute
)

func githubReleaseLatestURL() string {
	if testReleaseAPIURL != "" {
		return testReleaseAPIURL
	}
	return "https://api.github.com/repos/" + buildinfo.GitHubRepo + "/releases/latest"
}

func manifestJSONURL() string {
	if testManifestJSONURL != "" {
		return testManifestJSONURL
	}
	return buildinfo.LatestManifestURL()
}

// Test hooks (manifest_test.go only).
var (
	testManifestJSONURL string
	testReleaseAPIURL   string
)

func normalizeManifest(m *Manifest) {
	m.Version = strings.TrimSpace(m.Version)
	if m.DownloadURL == "" {
		m.DownloadURL = "https://github.com/" + buildinfo.GitHubRepo + "/releases/latest"
	}
	if m.ReleaseURL == "" && m.Version != "" {
		m.ReleaseURL = "https://github.com/" + buildinfo.GitHubRepo + "/releases/tag/v" + strings.TrimPrefix(m.Version, "v")
	}
}

// FetchManifest downloads the repo manifest, falling back to GitHub Releases API.
func FetchManifest(ctx context.Context, client *http.Client) (Manifest, error) {
	cacheMu.Lock()
	if time.Since(cache.at) < cacheTTL && (cache.manifest.Version != "" || cache.err != nil) {
		m, err := cache.manifest, cache.err
		cacheMu.Unlock()
		return m, err
	}
	cacheMu.Unlock()

	if client == nil {
		client = http.DefaultClient
	}

	m, err := fetchManifestJSON(ctx, client)
	if err == nil {
		storeManifestCache(m, nil)
		return m, nil
	}

	m, apiErr := fetchGitHubReleaseLatest(ctx, client)
	if apiErr == nil {
		storeManifestCache(m, nil)
		return m, nil
	}

	combined := fmt.Errorf("manifest: %v; releases API: %v", err, apiErr)
	storeManifestCache(Manifest{}, combined)
	return Manifest{}, combined
}

func storeManifestCache(m Manifest, err error) {
	cacheMu.Lock()
	cache = cachedManifest{at: time.Now(), manifest: m, err: err}
	cacheMu.Unlock()
}

// ResetManifestCache clears the in-memory manifest cache (tests).
func ResetManifestCache() {
	cacheMu.Lock()
	cache = cachedManifest{}
	cacheMu.Unlock()
}

func fetchManifestJSON(ctx context.Context, client *http.Client) (Manifest, error) {
	url := manifestJSONURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Manifest{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Vaultify/"+buildinfo.Version())

	resp, err := client.Do(req)
	if err != nil {
		return Manifest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("manifest HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Manifest{}, err
	}
	if strings.TrimSpace(m.Version) == "" {
		return Manifest{}, fmt.Errorf("manifest missing version")
	}
	m.Source = url
	normalizeManifest(&m)
	return m, nil
}

type ghReleaseLatest struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
}

func fetchGitHubReleaseLatest(ctx context.Context, client *http.Client) (Manifest, error) {
	url := githubReleaseLatestURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Manifest{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Vaultify/"+buildinfo.Version())

	resp, err := client.Do(req)
	if err != nil {
		return Manifest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("releases API HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return Manifest{}, err
	}
	var rel ghReleaseLatest
	if err := json.Unmarshal(body, &rel); err != nil {
		return Manifest{}, err
	}
	version := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(rel.TagName, "v"), "V"))
	if version == "" {
		return Manifest{}, fmt.Errorf("releases API missing tag_name")
	}
	m := Manifest{
		Version:     version,
		ReleaseURL:  rel.HTMLURL,
		DownloadURL: "https://github.com/" + buildinfo.GitHubRepo + "/releases/latest",
		Source:      url,
	}
	if rel.PublishedAt != "" {
		m.ReleasedAt = strings.Split(rel.PublishedAt, "T")[0]
	}
	normalizeManifest(&m)
	return m, nil
}

// Check compares the running version against the remote manifest or latest GitHub release.
func Check(ctx context.Context, current string, client *http.Client) CheckResult {
	now := time.Now().UTC().Format(time.RFC3339)
	current = strings.TrimSpace(current)
	res := CheckResult{
		Current:   current,
		CheckedAt: now,
		Repo:      buildinfo.GitHubRepo,
		Source:    buildinfo.LatestManifestURL(),
	}
	m, err := FetchManifest(ctx, client)
	if err != nil {
		res.Error = err.Error()
		res.Latest = current
		return res
	}
	res.Source = m.Source
	res.Latest = m.Version
	res.LatestPublished = m.Version
	res.ReleasedAt = m.ReleasedAt
	res.ReleaseURL = m.ReleaseURL
	res.DownloadURL = m.DownloadURL
	switch Compare(current, m.Version) {
	case -1:
		res.UpdateAvailable = true
	case 1:
		res.AheadOfPublished = true
	}
	return res
}
