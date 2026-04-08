package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Finding struct {
	PatternID       string `json:"pattern_id"`
	Severity        string `json:"severity"`
	Description     string `json:"description"`
	Root            string `json:"root"`
	RelativePath    string `json:"relative_path"`
	FullPath        string `json:"full_path"`
	LineNumber      int    `json:"line_number"`
	MatchSHA256     string `json:"match_sha256"`
	RedactedPreview string `json:"redacted_preview"`
	LineSnippet     string `json:"line_snippet,omitempty"`
	ProjectFolder   string `json:"project_folder,omitempty"`
	Value           string `json:"value,omitempty"`
}

// ProgressFunc is called as files are scanned.
type ProgressFunc func(progress, total int)

// FindingFunc is called each time a new finding is discovered.
type FindingFunc func(f Finding)

var excludeDirs = map[string]bool{
	"node_modules": true, ".git": true, ".svn": true, ".hg": true, "dist": true, "build": true,
	"out": true, "target": true, "bin": true, "obj": true, ".venv": true, "venv": true,
	"__pycache__": true, ".tox": true, "coverage": true, ".next": true, ".nuxt": true,
	".gradle": true, "Pods": true, ".terraform": true, "vendor": true, "site-packages": true,
	".cache": true, "packages": true, ".cargo": true, ".rustup": true, ".npm": true,
	".nuget": true, ".m2": true, "Carthage": true,
	"Program Files": true, "Program Files (x86)": true,
	"Windows": true, "Windows.old": true, "WinSxS": true,
	"$Recycle.Bin": true, "System Volume Information": true,
	"Recovery": true, "PerfLogs": true,
}

var scanExtensions = map[string]bool{
	".env": true, ".ps1": true, ".json": true, ".yml": true, ".yaml": true,
	".js": true, ".mjs": true, ".ts": true, ".tsx": true, ".jsx": true, ".py": true,
	".rb": true, ".go": true, ".java": true, ".properties": true, ".toml": true,
	".config": true, ".tf": true, ".tfvars": true, ".sh": true, ".bash": true,
	".xml": true, ".cs": true, ".php": true, ".sql": true, ".rs": true, ".vue": true,
	".local": true, ".development": true,
}

type Scanner struct {
	patterns []CompiledPattern
}

func NewScanner() *Scanner {
	return &Scanner{patterns: LoadPatterns()}
}

type scanWork struct {
	path string
	root string
}

func (s *Scanner) Scan(ctx context.Context, roots []string, onProgress ProgressFunc, onFinding FindingFunc) error {
	ch := make(chan scanWork, 256)

	go func() {
		defer close(ch)
		for _, root := range roots {
			s.walkDirChan(ctx, root, root, ch)
		}
	}()

	var mu sync.Mutex
	var scanned int
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for w := range ch {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(w scanWork) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			findings := s.scanFile(w.path, w.root)
			mu.Lock()
			scanned++
			n := scanned
			for _, f := range findings {
				onFinding(f)
			}
			mu.Unlock()
			if n%20 == 0 {
				onProgress(n, n+100)
			}
		}(w)
	}
	wg.Wait()
	onProgress(scanned, scanned)
	return nil
}

func (s *Scanner) walkDirChan(ctx context.Context, root, dir string, ch chan<- scanWork) {
	if ctx.Err() != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		name := e.Name()
		full := filepath.Join(dir, name)
		if e.IsDir() {
			if excludeDirs[name] {
				continue
			}
			s.walkDirChan(ctx, root, full, ch)
		} else {
			ext := filepath.Ext(name)
			if !scanExtensions[ext] && !strings.HasPrefix(name, ".env") {
				continue
			}
			info, err := e.Info()
			if err != nil || info.Size() > 5*1024*1024 {
				continue
			}
			ch <- scanWork{full, root}
		}
	}
}


func (s *Scanner) scanFile(fp, root string) []Finding {
	data, err := os.ReadFile(fp)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	rel, _ := filepath.Rel(root, fp)
	var results []Finding
	for lineNum, line := range lines {
		for _, pat := range s.patterns {
			locs := pat.Regex.FindAllStringIndex(line, -1)
			for _, loc := range locs {
				val := line[loc[0]:loc[1]]
				if len(val) < 8 {
					continue
				}
				h := sha256.Sum256([]byte(val))
				hash := fmt.Sprintf("%x", h)
				preview := val
				if len(val) > 10 {
					preview = val[:6] + "..." + val[len(val)-4:]
				}
				results = append(results, Finding{
					PatternID:       pat.ID,
					Severity:        pat.Severity,
					Description:     pat.Description,
					Root:            root,
					RelativePath:    rel,
					FullPath:        fp,
					LineNumber:      lineNum + 1,
					MatchSHA256:     hash,
					RedactedPreview: preview,
					LineSnippet:     line,
					Value:           val,
				})
			}
		}
	}
	return results
}
