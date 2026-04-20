package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type Finding struct {
	PatternID       string  `json:"pattern_id"`
	Severity        string  `json:"severity"`
	Description     string  `json:"description"`
	Root            string  `json:"root"`
	RelativePath    string  `json:"relative_path"`
	FullPath        string  `json:"full_path"`
	LineNumber      int     `json:"line_number"`
	MatchSHA256     string  `json:"match_sha256"`
	RedactedPreview string  `json:"redacted_preview"`
	LineSnippet     string  `json:"line_snippet,omitempty"`
	ProjectFolder   string  `json:"project_folder,omitempty"`
	Value           string  `json:"value,omitempty"`
	Entropy         float64 `json:"entropy"`
	DetectionLayer  string  `json:"detection_layer,omitempty"`
	ContextKey      string  `json:"context_key,omitempty"`
	Confidence      float64 `json:"confidence"`
}

// Confidence represents how likely a match is a real secret.
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// shannonEntropy computes the Shannon entropy of a string in bits per char.
// Real secrets typically have entropy > 3.5; code identifiers are < 3.0.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var ent float64
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

// Minimum entropy thresholds per pattern. Patterns with strong prefixes
// (ghp_, AKIA, sk-proj-) are inherently high-confidence so their
// entropy threshold is lower. Generic patterns need higher entropy.
var minEntropy = map[string]float64{
	"telegram_bot":   3.5,
	"jwt":            3.0,
	"mailgun":        3.2,
	"twilio":         3.0,
	"twilio_auth":    3.0,
	"databricks":     3.0,
	"openai_legacy":  3.0,
	"notion":         3.2,
}

func minEntropyFor(patternID string) float64 {
	if v, ok := minEntropy[patternID]; ok {
		return v
	}
	return 2.5
}

// lowNoiseDir returns true if the path is inside a directory whose
// contents are not user-authored code (app caches, browser profiles, etc).
var noiseDirFragments = []string{
	"\\AppData\\Local\\",
	"\\AppData\\Roaming\\",
	"/AppData/Local/",
	"/AppData/Roaming/",
	"\\Cache\\",
	"/Cache/",
	"\\CachedData\\",
	"\\Crashpad\\",
	"\\DawnCache\\",
	"\\GrShaderCache\\",
	"\\ShaderCache\\",
	"\\GPUCache\\",
	"\\IndexedDB\\",
	"\\Service Worker\\",
	"\\Local Storage\\",
	"\\Session Storage\\",
	"\\.nuget\\",
	"/.nuget/",
	"\\NuGet\\",
	"/NuGet/",
	"\\packages\\",
	"/packages/",
	"\\.m2\\",
	"/.m2/",
	"\\.gradle\\",
	"/.gradle/",
	"\\.cargo\\",
	"/.cargo/",
	"\\.npm\\",
	"/.npm/",
	"\\node_modules\\",
	"/node_modules/",
}

// highValueDir returns true if the path is typically user-authored source.
var highValueDirFragments = []string{
	"\\dev\\", "/dev/",
	"\\src\\", "/src/",
	"\\projects\\", "/projects/",
	"\\repos\\", "/repos/",
	"\\code\\", "/code/",
}

func pathConfidence(fp string) Confidence {
	fpLower := strings.ToLower(fp)
	for _, frag := range noiseDirFragments {
		if strings.Contains(fpLower, strings.ToLower(frag)) {
			return ConfLow
		}
	}
	for _, frag := range highValueDirFragments {
		if strings.Contains(fpLower, strings.ToLower(frag)) {
			return ConfHigh
		}
	}
	return ConfMedium
}

// looksLikeCode checks if the matched value contains patterns that suggest
// it's a code identifier rather than a real secret.
var codeIndicators = []string{
	"__", "function", "callback", "eventId", "handler", "className",
	"onClick", "onChange", "addEventListener", "prototype", "constructor",
	"toString", "undefined", "template", "component", "module.exports",
}

func looksLikeCode(val string) bool {
	lower := strings.ToLower(val)
	for _, ind := range codeIndicators {
		if strings.Contains(lower, strings.ToLower(ind)) {
			return true
		}
	}
	// Check for long English-like words (4+ consecutive lowercase letters
	// forming 3+ word-like segments) -- common in code identifiers, rare in secrets.
	// We detect this by looking for camelCase transitions in the portion
	// AFTER any known prefix (skip first 8 chars which may be a token prefix).
	check := val
	if len(check) > 8 {
		check = check[8:]
	}
	consecutiveLower := 0
	longWordSegments := 0
	for _, c := range check {
		if c >= 'a' && c <= 'z' {
			consecutiveLower++
		} else {
			if consecutiveLower >= 5 {
				longWordSegments++
			}
			consecutiveLower = 0
		}
	}
	if consecutiveLower >= 5 {
		longWordSegments++
	}
	if longWordSegments >= 3 {
		return true
	}
	return false
}

// Patterns that should bypass the looksLikeCode heuristic because their
// format is distinctive enough (URLs, PEM headers).
var bypassCodeCheck = map[string]bool{
	"slack_webhook":     true,
	"private_key_block": true,
}

// contextPattern matches compound key names containing secret-related words
// in assignment expressions (key = "value", key: "value", key="value").
// PatternOpSecretRef is the synthetic pattern ID for 1Password CLI inject references (op://…).
// These are surfaced as informational “good practice” rows, not remediation targets.
const PatternOpSecretRef = "op_secret_ref"

// opInjectRefRx matches op:// vault references on a line (stops at whitespace and common string delimiters).
var opInjectRefRx = regexp.MustCompile(`op://[^\s"'<>\t\r\n]+`)

var contextPattern = regexp.MustCompile(
	`(?i)([\w]*(?:` +
		`api_key|apikey|api_secret|api_token|` +
		`secret_key|secret_access|client_secret|` +
		`auth_token|access_token|bearer_token|bot_token|` +
		`password|passwd|` +
		`private_key|encryption_key|signing_key|` +
		`database_url|db_url|db_password|db_pass|` +
		`connection_string|conn_str|` +
		`webhook_url|webhook_secret` +
		`)[\w]*)\s*[=:]\s*["'\x60]?([^"'\x60\s\r\n]{8,})["'\x60]?`)

var contextPlaceholders = map[string]bool{
	"changeme": true, "change_me": true, "CHANGEME": true,
	"replace_me": true, "REPLACE_ME": true, "your_token_here": true,
	"YOUR_TOKEN_HERE": true, "xxx": true, "TODO": true,
	"placeholder": true, "PLACEHOLDER": true, "example": true,
	"EXAMPLE": true, "test": true, "TEST": true, "dummy": true,
	"REDACTED": true, "REDACTED_BY_VAULTIFY": true,
}

// isRedactedOrVaultSecretRef skips values Vaultify already replaced, or 1Password CLI inject refs (op://…)
// which are not literal secrets in the file.
func isRedactedOrVaultSecretRef(val string) bool {
	v := strings.TrimSpace(val)
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "op://") {
		return true
	}
	if strings.EqualFold(v, "REDACTED") || strings.EqualFold(v, "REDACTED_BY_VAULTIFY") {
		return true
	}
	if strings.Contains(strings.ToLower(v), "redacted_by_vaultify") {
		return true
	}
	return false
}

// Paths where context-style key matching is dominated by clones, caches, and fixtures.
// Layer 1 (value patterns) may still run with their own path-aware thresholds.
var contextLowTrustPathFragments = []string{
	"/cache/", "/.cache/", "/tmp/", "/temp/",
	"/fixtures/", "/testdata/", "/__tests__/", "/mocks/", "/mock/",
	"/_repo/", "/.gradle/caches/", "/.cargo/registry/", "/site-packages/",
	"/coverage/", "/.next/", "/.nuget/", "/node_modules/", "/bower_components/",
	"/.pnpm-store/", "/.yarn/", "/vendor/bundle/", "/gopath/pkg/",
	"/openclaw", "/.gem/", "/.bundle/",
}

func isContextExampleOrTemplateFile(fp string) bool {
	base := strings.ToLower(filepath.Base(fp))
	if strings.HasPrefix(base, ".env") {
		if strings.HasSuffix(base, ".example") || strings.HasSuffix(base, ".sample") ||
			strings.HasSuffix(base, ".template") || strings.HasSuffix(base, ".dist") {
			return true
		}
	}
	if strings.HasSuffix(base, ".env.example") || strings.HasSuffix(base, ".env.sample") {
		return true
	}
	return false
}

func shouldSkipContextLayer(fp string) bool {
	if isContextExampleOrTemplateFile(fp) {
		return true
	}
	low := filepath.ToSlash(strings.ToLower(fp))
	for _, frag := range contextLowTrustPathFragments {
		if strings.Contains(low, frag) {
			return true
		}
	}
	return false
}

func isRepeatingCharString(val string) bool {
	if len(val) < 10 {
		return false
	}
	first := val[0]
	for i := 1; i < len(val); i++ {
		if val[i] != first {
			return false
		}
	}
	return true
}

func contextPlaceholderHeuristic(val string) bool {
	if isRepeatingCharString(val) {
		return true
	}
	lower := strings.ToLower(val)
	prefixes := []string{
		"your_", "insert_", "replace_with_", "replace_", "enter_your_", "my_api_",
		"xxx", "test_fake_", "fake_", "dummy_", "sample_", "mock_", "lorem",
		"foobar", "foo_bar", "bar_baz", "example_", "ex_",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	// Common test-mode prefixes (context layer only; value patterns keep their own rules)
	if strings.HasPrefix(lower, "pk_test_") || strings.HasPrefix(lower, "sk_test_") ||
		strings.HasPrefix(lower, "whsec_test_") || strings.HasPrefix(lower, "rk_test_") {
		return true
	}
	return false
}

// contextEntropyFloor is the minimum Shannon entropy for a context-only match in trusted paths.
const contextEntropyFloor = 3.25

// contextRHSIsNonLiteral skips assignments whose RHS is clearly code (function / constructor calls)
// rather than a literal secret — e.g. access_token = create_access_token(...),
// access_token_expires = timedelta(minutes=settings.FOO).
func contextRHSIsNonLiteral(val string) bool {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return false
	}
	paren := strings.IndexByte(trimmed, '(')
	if paren <= 0 {
		return false
	}
	fn := strings.TrimSpace(trimmed[:paren])
	if fn == "" {
		return false
	}
	for _, c := range fn {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return len(fn) >= 1
}

func contextValueAllowed(fp, val string, ent float64) bool {
	if contextPlaceholderHeuristic(val) {
		return false
	}
	if looksLikeCode(val) {
		return false
	}
	min := contextEntropyFloor
	if pathConfidence(fp) == ConfLow {
		min += 0.45
	}
	return ent >= min
}

func isEnvFile(fp string) bool {
	name := filepath.Base(fp)
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, ".env") || lower == "credentials" ||
		lower == "config" || lower == "secrets" || lower == ".npmrc" ||
		lower == ".pypirc" || lower == ".netrc"
}

func computeConfidence(f *Finding, fileContextCount int) float64 {
	if f.DetectionLayer == "vault_ref" {
		return 1.0
	}
	score := 0.0
	if f.Entropy >= 4.5 {
		score += 0.4
	} else if f.Entropy >= 3.5 {
		score += 0.3
	} else if f.Entropy >= 2.5 {
		score += 0.2
	}
	switch f.DetectionLayer {
	case "both":
		score += 0.35
	case "value":
		score += 0.3
	case "context":
		score += 0.2
	}
	if isEnvFile(f.FullPath) {
		score += 0.15
	}
	if fileContextCount > 3 {
		score += 0.1
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// isLikelySecret evaluates whether a match is a real secret using
// entropy, path context, and content heuristics.
func isLikelySecret(pat CompiledPattern, val, filePath string) bool {
	if !bypassCodeCheck[pat.ID] && looksLikeCode(val) {
		return false
	}

	ent := shannonEntropy(val)
	threshold := minEntropyFor(pat.ID)
	if pat.MinEntropy > 0 {
		threshold = pat.MinEntropy
	}

	pathConf := pathConfidence(filePath)

	switch pathConf {
	case ConfLow:
		threshold += 0.5
	case ConfHigh:
		threshold -= 0.3
	}

	return ent >= threshold
}

// ProgressFunc is called as files are scanned. currentPath is the file currently being processed.
type ProgressFunc func(progress, total int, currentPath string)

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
	"BraveSoftware": true, "Google": true, "Mozilla": true,
	"Microsoft Edge": true, "Extensions": true, "User Data": true,
	"YandexBrowser": true, "Yandex": true, "Opera Software": true,
	"Vivaldi": true, "Chromium": true, "Epic Privacy Browser": true,
	"$Recycle.Bin": true, "System Volume Information": true,
	"Recovery": true, "PerfLogs": true,
}

var scanExtensions = map[string]bool{
	".env": true, ".ps1": true, ".json": true, ".yml": true, ".yaml": true,
	".js": true, ".mjs": true, ".ts": true, ".tsx": true, ".jsx": true, ".py": true,
	".rb": true, ".go": true, ".java": true, ".properties": true, ".toml": true,
	".config": true, ".cfg": true, ".ini": true, ".conf": true,
	".tf": true, ".tfvars": true, ".sh": true, ".bash": true, ".zsh": true,
	".xml": true, ".cs": true, ".php": true, ".sql": true, ".rs": true, ".vue": true,
	".local": true, ".development": true,
	".kt": true, ".scala": true, ".swift": true, ".gradle": true, ".sbt": true,
	".r": true, ".lua": true, ".pl": true, ".pm": true,
	".pem": true, ".key": true, ".crt": true,
	".dockerfile": true, ".helmfile": true,
}

var scanFilenames = map[string]bool{
	".npmrc": true, ".pypirc": true, ".netrc": true, ".gitconfig": true,
	"credentials": true, "config": true, "secrets": true,
	"Dockerfile": true, "Makefile": true, "Vagrantfile": true,
	".bashrc": true, ".zshrc": true, ".profile": true, ".bash_profile": true,
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
	sem := make(chan struct{}, 16)
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
				onProgress(n, n+100, w.path)
			}
		}(w)
	}
	wg.Wait()
	onProgress(scanned, scanned, "")
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
			if !scanExtensions[ext] && !scanFilenames[name] && !strings.HasPrefix(name, ".env") {
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
	seen := map[string]int{}
	var results []Finding
	contextCount := 0

	for lineNum, line := range lines {
		// Lines we already redacted in place (or paths embedding that marker) are never new secrets.
		if strings.Contains(strings.ToLower(line), "redacted_by_vaultify") {
			continue
		}

		hasAssign := strings.ContainsAny(line, "=:")

		// Layer 2: Context detection (key name matching on assignment lines)
		if hasAssign && !shouldSkipContextLayer(fp) {
			matches := contextPattern.FindAllStringSubmatchIndex(line, -1)
			for _, m := range matches {
				if len(m) < 6 {
					continue
				}
				keyName := line[m[2]:m[3]]
				val := line[m[4]:m[5]]
				if len(val) < 8 || contextPlaceholders[val] || isRedactedOrVaultSecretRef(val) {
					continue
				}
				if contextRHSIsNonLiteral(val) {
					continue
				}
				ent := shannonEntropy(val)
				if !contextValueAllowed(fp, val, ent) {
					continue
				}
				h := sha256.Sum256([]byte(val))
				hash := fmt.Sprintf("%x", h)
				preview := val
				if len(val) > 10 {
					preview = val[:6] + "..." + val[len(val)-4:]
				}
				contextCount++
				idx := len(results)
				seen[hash] = idx
				results = append(results, Finding{
					PatternID:       keyName,
					Severity:        "high",
					Description:     "Context-detected credential: " + keyName,
					Root:            root,
					RelativePath:    rel,
					FullPath:        fp,
					LineNumber:      lineNum + 1,
					MatchSHA256:     hash,
					RedactedPreview: preview,
					LineSnippet:     line,
					Value:           val,
					Entropy:         math.Round(ent*100) / 100,
					DetectionLayer:  "context",
					ContextKey:      keyName,
				})
			}
		}

		// Layer 1: Value pattern detection (all lines)
		for _, pat := range s.patterns {
			if pat.Prefix != "" && !strings.Contains(line, pat.Prefix) {
				continue
			}
			locs := pat.Regex.FindAllStringIndex(line, -1)
			for _, loc := range locs {
				val := line[loc[0]:loc[1]]
				if len(val) < 8 || isRedactedOrVaultSecretRef(val) {
					continue
				}
				if !isLikelySecret(pat, val, fp) {
					continue
				}
				h := sha256.Sum256([]byte(val))
				hash := fmt.Sprintf("%x", h)
				preview := val
				if len(val) > 10 {
					preview = val[:6] + "..." + val[len(val)-4:]
				}
				ent := shannonEntropy(val)

				if idx, exists := seen[hash]; exists {
					// Layer 1 enriches existing Layer 2 finding
					results[idx].PatternID = pat.ID
					results[idx].Severity = pat.Severity
					results[idx].Description = pat.Description
					results[idx].DetectionLayer = "both"
					results[idx].Entropy = math.Round(ent*100) / 100
				} else {
					seen[hash] = len(results)
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
						Entropy:         math.Round(ent*100) / 100,
						DetectionLayer:  "value",
					})
				}
			}
		}

		// Layer: 1Password secret references (op://) — not literals; show as good practice in Review.
		if strings.Contains(line, "op://") {
			for _, refLoc := range opInjectRefRx.FindAllStringIndex(line, -1) {
				ref := strings.TrimRight(strings.TrimSpace(line[refLoc[0]:refLoc[1]]), `,.;)`)
				if !strings.HasPrefix(ref, "op://") || len(ref) < len("op://a/b") {
					continue
				}
				h := sha256.Sum256([]byte(ref))
				hash := fmt.Sprintf("%x", h)
				if _, exists := seen[hash]; exists {
					continue
				}
				seen[hash] = len(results)
				preview := ref
				if len(ref) > 44 {
					preview = ref[:18] + "..." + ref[len(ref)-14:]
				}
				results = append(results, Finding{
					PatternID:       PatternOpSecretRef,
					Severity:        "info",
					Description:     "1Password secret reference (op://) — value resolved from vault, not stored in repo",
					Root:            root,
					RelativePath:    rel,
					FullPath:        fp,
					LineNumber:      lineNum + 1,
					MatchSHA256:     hash,
					RedactedPreview: preview,
					LineSnippet:     line,
					Value:           ref,
					Entropy:         0,
					DetectionLayer:  "vault_ref",
				})
			}
		}
	}

	// Post-validate: compute confidence scores
	for i := range results {
		results[i].Confidence = computeConfidence(&results[i], contextCount)
	}

	return results
}

// RecoverPlaintext re-derives the secret value from disk for a finding whose Value was stripped at rest.
// Session JSON never stores plaintext; this mirrors scanFile: value-regex matches first, then context-layer submatches.
func RecoverPlaintext(f Finding) string {
	if f.PatternID == PatternOpSecretRef {
		return ""
	}
	if f.FullPath == "" || f.LineNumber < 1 || f.MatchSHA256 == "" {
		return ""
	}
	data, err := os.ReadFile(f.FullPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if f.LineNumber < 1 || f.LineNumber > len(lines) {
		return ""
	}
	line := strings.TrimSuffix(lines[f.LineNumber-1], "\r")
	want := f.MatchSHA256

	patterns := LoadPatterns()
	for _, pat := range patterns {
		if pat.ID != f.PatternID {
			continue
		}
		for _, loc := range pat.Regex.FindAllStringIndex(line, -1) {
			val := line[loc[0]:loc[1]]
			if len(val) < 8 {
				continue
			}
			h := sha256.Sum256([]byte(val))
			if fmt.Sprintf("%x", h) == want {
				return val
			}
		}
	}

	// Context-only findings use the variable name as pattern_id, not a catalogue pattern ID.
	matches := contextPattern.FindAllStringSubmatchIndex(line, -1)
	for _, m := range matches {
		if len(m) < 6 {
			continue
		}
		val := line[m[4]:m[5]]
		if len(val) < 8 {
			continue
		}
		h := sha256.Sum256([]byte(val))
		if fmt.Sprintf("%x", h) == want {
			return val
		}
	}
	return ""
}
