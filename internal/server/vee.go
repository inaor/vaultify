package server

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vaultify/vaultify/internal/buildinfo"
	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
	"github.com/vaultify/vaultify/internal/vault"
)

type veeChatContext struct {
	CurrentPage    string         `json:"current_page"`
	Decisions      map[string]int `json:"decisions"`
	TotalFindings  int            `json:"total_findings"`
	ScanStatus     string         `json:"scan_status"`
}

type veeChatRequest struct {
	SessionID string          `json:"session_id"`
	Message   string          `json:"message"`
	Provider  string          `json:"provider"`
	Context   *veeChatContext `json:"context,omitempty"`
}

// veeProviderStatus is the wire shape for one Vee provider in
// /api/vee/providers. Provenance fields let the UI distinguish
// vault-sourced keys from user-pasted ones and show a
// "validated 2 s ago" status without the user running a message.
type veeProviderStatus struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	NeedsKey               bool   `json:"needs_key"`
	HasKey                 bool   `json:"has_key"`
	Available              bool   `json:"available"`
	Model                  string `json:"model"`
	KeySource              string `json:"key_source,omitempty"`       // "vault" | "user_entered" | "unknown"
	VaultLocation          string `json:"vault_location,omitempty"`   // op://<vault>/<title>/credential
	ModelSource            string `json:"model_source,omitempty"`     // "vault" | "default"
	KeyLastValidatedAt     string `json:"key_last_validated_at,omitempty"`
	KeyLastValidatedStatus string `json:"key_last_validated_status,omitempty"` // ok | unauthorized | rate_limited | network | never
	VaultChecked           bool   `json:"vault_checked"`
}

type veeKeyRequest struct {
	Provider        string `json:"provider"`
	Key             string `json:"key,omitempty"`
	ValidationToken string `json:"validation_token,omitempty"`
	Model           string `json:"model"`
}

// --- Validation token store (5-minute TTL) ---------------------------

type veeValidationEntry struct {
	Provider  string
	Key       string // memory-only; never persisted
	CreatedAt time.Time
}

type veeValidationStore struct {
	mu      sync.Mutex
	entries map[string]*veeValidationEntry
}

var veeValidations = &veeValidationStore{entries: make(map[string]*veeValidationEntry)}

const veeValidationTTL = 5 * time.Minute

func (s *veeValidationStore) put(provider, key string) string {
	s.sweepLocked() // cheap, and stops the map growing unbounded
	id := randomValidationToken()
	s.mu.Lock()
	s.entries[id] = &veeValidationEntry{Provider: provider, Key: key, CreatedAt: time.Now()}
	s.mu.Unlock()
	return id
}

func (s *veeValidationStore) consume(id string) (*veeValidationEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return nil, false
	}
	delete(s.entries, id)
	if time.Since(e.CreatedAt) > veeValidationTTL {
		return nil, false
	}
	return e, true
}

func (s *veeValidationStore) sweepLocked() {
	s.mu.Lock()
	now := time.Now()
	for id, e := range s.entries {
		if now.Sub(e.CreatedAt) > veeValidationTTL {
			delete(s.entries, id)
		}
	}
	s.mu.Unlock()
}

func randomValidationToken() string {
	var b [12]byte
	if _, err := cryptoRand.Read(b[:]); err != nil {
		return fmt.Sprintf("vt-%d", time.Now().UnixNano())
	}
	return "vt-" + hex.EncodeToString(b[:])
}

// --- Per-provider last-validated cache (memory only) -----------------

type veeValidationRecord struct {
	At     time.Time
	Status string // ok | unauthorized | rate_limited | network | never
}

var (
	veeLastValidatedMu sync.Mutex
	veeLastValidated   = map[string]veeValidationRecord{}
)

func setLastValidated(provider, status string) {
	veeLastValidatedMu.Lock()
	veeLastValidated[provider] = veeValidationRecord{At: time.Now(), Status: status}
	veeLastValidatedMu.Unlock()
}

func getLastValidated(provider string) veeValidationRecord {
	veeLastValidatedMu.Lock()
	defer veeLastValidatedMu.Unlock()
	if r, ok := veeLastValidated[provider]; ok {
		return r
	}
	return veeValidationRecord{}
}

const veeSystemPromptTemplate = `You are Vee, Vaultify's security assistant. You speak British English, are concise, professional, and approachable.
You are analysing a credential scan for session %s.

FINDINGS (%d total, %d unique secrets):
%s

PATTERN SUMMARY:
%s

USER CONTEXT:
%s

You help the user:
- Understand which findings are genuine risks vs false positives
- Prioritise remediation (critical severity first)
- Suggest whether to Vaultify (store in vault), Remove from code, or send false positives to the Junkyard (excluded on future scans)
- Generate executive summaries for governance reporting
- Explain what each pattern type means in plain language
- ACTIVELY detect and flag likely false positives. Common FP indicators:
  * Findings in AppData, Cache, browser profiles, or third-party app directories
  * Values containing code identifiers like __eventId__, callback, handler, className
  * Low-entropy matches (repetitive patterns, English words)
  * Example/placeholder keys (containing "EXAMPLE", "test", "sample", "placeholder")
  * Matches in SDK test fixtures or documentation files

RULES:
- NEVER output any string that looks like a credential, API key, token, or secret -- even if partially visible in the preview
- Always refer to secrets by their pattern type and file location, e.g. "the AWS key in backend/.env line 3"
- If a user asks you to show a key value, decline and explain why
- The "preview" field is already redacted -- do not attempt to reconstruct or guess the full value
- Never access the filesystem or any data outside this session
- Only discuss findings from this session
- If asked about other data or sessions, decline politely
- Keep responses concise -- bullet points over paragraphs
- Use UK English spelling
- When the user is on the Review & Decide page, reference specific findings and suggest actions
- When the user is on the Reports page, focus on trends and governance
- When asked for a summary, always include a "Likely False Positives" section`

func (srv *Server) buildVeeContext(sessionID string, ctx *veeChatContext) (string, error) {
	if sessionID == "" {
		srv.state.mu.Lock()
		sessionID = srv.state.SessionID
		srv.state.mu.Unlock()
	}
	if sessionID == "" {
		if sessions, err := srv.sessions.List(); err == nil && len(sessions) > 0 {
			sessionID = sessions[0].ID
		}
	}
	if sessionID == "" {
		return "", fmt.Errorf("no active session")
	}

	userCtx := "No additional context."
	if ctx != nil {
		parts := []string{}
		if ctx.CurrentPage != "" {
			parts = append(parts, fmt.Sprintf("User is viewing: %s page", ctx.CurrentPage))
		}
		if ctx.ScanStatus != "" {
			parts = append(parts, fmt.Sprintf("Scan status: %s", ctx.ScanStatus))
		}
		if ctx.Decisions != nil {
			gy := ctx.Decisions["graveyard"]
			if ctx.Decisions["dismiss"] > 0 {
				gy += ctx.Decisions["dismiss"]
			}
			parts = append(parts, fmt.Sprintf("Decisions made: vault=%d, remove=%d, junkyard=%d, pending=%d",
				ctx.Decisions["vault"], ctx.Decisions["remove"], gy, ctx.Decisions["pending"]))
		}
		if len(parts) > 0 {
			userCtx = strings.Join(parts, "\n")
		}
	}

	// Also load decisions from disk if available
	decCtx := ""
	if sessionID != "" && session.IsValidID(sessionID) {
		decPath := filepath.Join(srv.sessions.Dir(sessionID), "decisions.json")
		if data, err := os.ReadFile(decPath); err == nil {
			decCtx = "\n\nSAVED DECISIONS:\n" + string(data[:min(len(data), 2000)])
		}
	}
	userCtx += decCtx

	type compactFinding struct {
		Pattern  string `json:"pattern"`
		Severity string `json:"severity"`
		Preview  string `json:"preview"`
		Path     string `json:"path"`
		Line     int    `json:"line"`
	}

	buildFromFindings := func(findings []scanner.Finding) string {
		patMap := map[string]int{}
		uniqueHashes := map[string]bool{}
		for _, f := range findings {
			patMap[f.PatternID]++
			uniqueHashes[f.MatchSHA256] = true
		}

		maxFindings := 60
		subset := findings
		if len(subset) > maxFindings {
			subset = subset[:maxFindings]
		}
		compact := make([]compactFinding, len(subset))
		for i, f := range subset {
			prev := f.RedactedPreview
			if len(prev) > 8 {
				prev = prev[:4] + "..." + prev[len(prev)-2:]
			}
			compact[i] = compactFinding{
				Pattern:  f.PatternID,
				Severity: f.Severity,
				Preview:  prev,
				Path:     f.RelativePath,
				Line:     f.LineNumber,
			}
		}
		findingsJSON, _ := json.Marshal(compact)

		keys := make([]string, 0, len(patMap))
		for k := range patMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		patSummary := ""
		for _, k := range keys {
			patSummary += fmt.Sprintf("  %s: %d\n", k, patMap[k])
		}

		return fmt.Sprintf(veeSystemPromptTemplate, sessionID, len(findings), len(uniqueHashes), string(findingsJSON), patSummary, userCtx)
	}

	s, err := srv.sessions.Get(sessionID)
	if err != nil {
		srv.state.mu.Lock()
		findings := make([]scanner.Finding, len(srv.state.Findings))
		copy(findings, srv.state.Findings)
		srv.state.mu.Unlock()
		if len(findings) == 0 {
			return "", fmt.Errorf("session not found and no active scan")
		}
		return buildFromFindings(findings), nil
	}

	return buildFromFindings(s.Findings), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

const veeNoScanPrompt = `You are Vee, Vaultify's security assistant. You speak British English, are concise, professional, and approachable.
No scan data is loaded. You can:
- Explain what Vaultify does (scans for plaintext secrets, helps vault or remove them)
- Guide the user to either click "Start Scan" on the Scan tab, or load a previous session from the Reports tab
- Answer general questions about secrets management, credential hygiene, and vault best practices
- Explain what each pattern type detects (AWS keys, GitHub tokens, Slack tokens, etc.)

Keep responses concise. Use UK English spelling.`

func (srv *Server) handleVeeChat(w http.ResponseWriter, r *http.Request) {
	var req veeChatRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.SessionID != "" && !session.IsValidID(req.SessionID) {
		httpError(w, http.StatusBadRequest, "invalid session id")
		return
	}

	systemPrompt, err := srv.buildVeeContext(req.SessionID, req.Context)
	if err != nil {
		systemPrompt = veeNoScanPrompt
	}

	providerID := req.Provider
	if providerID == "" {
		providerID = "openai"
	}
	provider := ProviderByID(providerID)
	if provider == nil {
		httpError(w, http.StatusBadRequest, "unknown provider: %s", providerID)
		return
	}

	apiKey := srv.getVeeKey(providerID)
	if apiKey == "" && providerID != "ollama" {
		httpError(w, http.StatusBadRequest, "No API key found for %s. Store it in your Vaultify vault first.", providerID)
		return
	}

	// Response is a plain-text stream of raw deltas (no SSE framing on
	// the Vaultify↔browser hop). The browser reads with a ReadableStream
	// reader and appends as chunks arrive.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	// Resolve the model the request will actually run on so we can both
	// pass it down to the provider AND tell Vee about it. Without this
	// extra system-prompt line the LLM has no way to answer "which
	// model are you?" with anything more specific than "GPT" / "Claude"
	// — the user just hit that on a real chat.
	storedModel := srv.getVeeModel(providerID)
	resolvedModel := storedModel
	if resolvedModel == "" || resolvedModel == "default" {
		resolvedModel = provider.DefaultModel()
	}
	systemPrompt = fmt.Sprintf(
		"You are running on the %q model via the %s provider. "+
			"If the user asks which model or which AI you are, give them this exact identifier.\n\n%s",
		resolvedModel, providerID, systemPrompt,
	)

	in := ChatInput{
		Model:        storedModel,
		Key:          apiKey,
		SystemPrompt: systemPrompt,
		UserMessage:  req.Message,
	}
	srv.addAuditEntry("vee.chat.started", fmt.Sprintf("provider=%s model=%s", providerID, resolvedModel))

	text, perr := provider.Chat(r.Context(), in, w)
	if perr != nil {
		veeLog().Warn("chat.error",
			slog.String("provider", perr.Provider),
			slog.Int("status", perr.Status),
			slog.String("category", string(perr.Category)),
			slog.String("message", truncateStr(perr.Message, 400)),
		)
		srv.addAuditEntry("vee.chat.failed", fmt.Sprintf("provider=%s category=%s status=%d", perr.Provider, perr.Category, perr.Status))
		if text == "" {
			// Nothing streamed yet → the client body is empty, safe to
			// surface a user-facing prefix instead of a silent failure.
			_, _ = io.WriteString(w, "[Error: "+describeProviderError(perr)+"]")
		} else {
			_, _ = io.WriteString(w, "\n\n[Interrupted: "+describeProviderError(perr)+"]")
		}
		return
	}
	srv.addAuditEntry("vee.chat.completed", fmt.Sprintf("provider=%s bytes=%d", providerID, len(text)))
}

// describeProviderError renders a short user-facing string. Full detail
// still goes to the Logs tab via the slog record.
func describeProviderError(p *ProviderError) string {
	if p == nil {
		return "unknown error"
	}
	switch p.Category {
	case ErrAuth:
		return "provider rejected the API key (401/403). Check the stored key in Vee settings."
	case ErrRateLimit:
		return "provider rate limit hit (429). Try again in a few seconds."
	case ErrQuota:
		return "provider quota exhausted. Check your plan or billing."
	case ErrNetwork:
		return "could not reach provider. Check your internet connection."
	case ErrBadInput:
		return "provider rejected the request. Model or schema mismatch — see Logs tab."
	case ErrProviderUp:
		return "provider is currently having issues (5xx)."
	}
	if p.Message != "" {
		return truncateStr(p.Message, 180)
	}
	return "unknown error"
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (srv *Server) handleVeeProviders(w http.ResponseWriter, r *http.Request) {
	providers := []veeProviderStatus{
		{ID: "openai", Name: "GPT", NeedsKey: true},
		{ID: "anthropic", Name: "Claude", NeedsKey: true},
		{ID: "gemini", Name: "Gemini", NeedsKey: true},
		{ID: "ollama", Name: "Ollama", NeedsKey: false},
	}

	vaultName := srv.getVeeVaultName()
	checkVault := r.URL.Query().Get("check") == "1"
	attemptedCheck := false
	if checkVault && srv.activeBackend().SupportsVeeCredentialStore() {
		if opPath, err := exec.LookPath("op"); err == nil {
			attemptedCheck = true
			slots := vault.VeeProviderKeyScan(opPath, vaultName)
			for i := range providers {
				if !providers[i].NeedsKey {
					continue
				}
				if s, ok := slots[providers[i].ID]; ok {
					providers[i].HasKey = s.HasKey
					providers[i].Available = s.HasKey
					providers[i].Model = s.Model
					if s.HasKey {
						providers[i].KeySource = "vault"
						providers[i].VaultLocation = fmt.Sprintf("op://%s/vee-%s-key/credential", vaultName, providers[i].ID)
						if s.Model != "" && s.Model != "default" {
							providers[i].ModelSource = "vault"
						}
					}
				}
			}
		}
	}
	for i := range providers {
		providers[i].VaultChecked = attemptedCheck
		if providers[i].NeedsKey && providers[i].HasKey && providers[i].KeySource == "" {
			providers[i].KeySource = "unknown"
		}
		rec := getLastValidated(providers[i].ID)
		if !rec.At.IsZero() {
			providers[i].KeyLastValidatedAt = rec.At.UTC().Format(time.RFC3339)
			providers[i].KeyLastValidatedStatus = rec.Status
		} else if providers[i].HasKey {
			providers[i].KeyLastValidatedStatus = "never"
		}
		if !providers[i].NeedsKey {
			providers[i].Available = isOllamaRunning()
		}
	}

	writeJSON(w, http.StatusOK, providers)
}

// validateProviderKey runs the provider-specific probe and returns the
// list of usable models plus a high-level reason category. Shared
// between "paste a new key" and "validate the key already stored in
// the vault" flows so both surfaces report the same errors.
func validateProviderKey(provider, key string) (models []string, reason string) {
	switch provider {
	case "openai":
		httpReq, _ := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
		httpReq.Header.Set("Authorization", "Bearer "+key)
		client := &http.Client{Timeout: 8 * time.Second}
		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, "network"
		}
		defer resp.Body.Close()
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return nil, "unauthorized"
		}
		if resp.StatusCode == 429 {
			return nil, "rate_limited"
		}
		if resp.StatusCode != 200 {
			return nil, "unknown"
		}
		var result struct {
			Data []struct{ ID string `json:"id"` } `json:"data"`
		}
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &result)
		for _, m := range result.Data {
			if strings.Contains(m.ID, "gpt") {
				models = append(models, m.ID)
			}
		}
		sort.Strings(models)
		if len(models) == 0 {
			return nil, "no_models"
		}
		return models, "ok"
	case "anthropic":
		// Anthropic has no public list endpoint; accept at face value
		// when the key shape is non-empty. Real validation happens on
		// first chat. Reason "ok" is returned so the UI can move on.
		if strings.TrimSpace(key) == "" {
			return nil, "unauthorized"
		}
		return []string{"claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-3-5-sonnet-20241022"}, "ok"
	case "gemini":
		if strings.TrimSpace(key) == "" {
			return nil, "unauthorized"
		}
		return []string{"gemini-2.0-flash", "gemini-2.5-flash-preview-05-20", "gemini-2.5-pro-preview-05-06"}, "ok"
	case "ollama":
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://localhost:11434/api/tags")
		if err != nil {
			return nil, "network"
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, "unknown"
		}
		var result struct {
			Models []struct{ Name string `json:"name"` } `json:"models"`
		}
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &result)
		for _, m := range result.Models {
			models = append(models, m.Name)
		}
		if len(models) == 0 {
			return nil, "no_models"
		}
		return models, "ok"
	}
	return nil, "unknown_provider"
}

func (srv *Server) handleVeeModels(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
		Key      string `json:"key"`
	}
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	srv.addAuditEntry("vee.key.validate_started", fmt.Sprintf("provider=%s", req.Provider))

	models, reason := validateProviderKey(req.Provider, req.Key)
	if reason != "ok" {
		srv.addAuditEntry("vee.key.validate_failed", fmt.Sprintf("provider=%s reason=%s", req.Provider, reason))
		// Keep legacy shape so the existing client keeps working.
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "models": []string{}, "reason": reason})
		return
	}

	// Issue a short-lived token so the browser never has to hold the
	// pasted key between "validate" and "store". Survives a paused tab.
	token := veeValidations.put(req.Provider, req.Key)
	srv.addAuditEntry("vee.key.validated", fmt.Sprintf("provider=%s model_count=%d", req.Provider, len(models)))
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":            true,
		"models":           models,
		"validation_token": token,
		"reason":           "ok",
	})
}

// handleVeeValidateStoredKey probes the provider with the key already
// stored in the configured Vee vault, updates the last-validated cache,
// and returns the status so the UI can show a green/red dot without
// sending a chat message.
func (srv *Server) handleVeeValidateStoredKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
	}
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Provider == "" {
		httpError(w, http.StatusBadRequest, "provider is required")
		return
	}
	key := srv.getVeeKey(req.Provider)
	if key == "" {
		setLastValidated(req.Provider, "never")
		writeJSON(w, http.StatusOK, map[string]any{
			"provider": req.Provider,
			"status":   "no_key",
			"reason":   "no stored key in vault",
		})
		return
	}
	_, reason := validateProviderKey(req.Provider, key)
	setLastValidated(req.Provider, reason)
	srv.addAuditEntry("vee.key.stored_validated", fmt.Sprintf("provider=%s status=%s", req.Provider, reason))
	rec := getLastValidated(req.Provider)
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":   req.Provider,
		"status":     reason,
		"checked_at": rec.At.UTC().Format(time.RFC3339),
	})
}

func (srv *Server) handleVeeStoreKey(w http.ResponseWriter, r *http.Request) {
	var req veeKeyRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Provider == "" {
		httpError(w, http.StatusBadRequest, "provider is required")
		return
	}

	// Token flow preferred; legacy key-in-body still accepted.
	var key string
	var source string
	if req.ValidationToken != "" {
		entry, ok := veeValidations.consume(req.ValidationToken)
		if !ok {
			httpError(w, http.StatusBadRequest, "validation token expired or already used — paste the key again")
			return
		}
		if entry.Provider != req.Provider {
			httpError(w, http.StatusBadRequest, "validation token does not match provider")
			return
		}
		key = entry.Key
		source = "user_entered"
	} else if req.Key != "" {
		key = req.Key
		source = "user_entered"
	} else {
		httpError(w, http.StatusBadRequest, "provide either key or validation_token")
		return
	}

	b := srv.activeBackend()
	if !b.SupportsVeeCredentialStore() {
		httpError(w, http.StatusBadRequest, "Storing Vee API keys requires 1Password as the active vault in the sidebar.")
		return
	}
	model := req.Model
	if model == "" {
		model = "default"
	}
	vaultName := srv.getVeeVaultName()
	stored, changed, err := b.StoreVeeProviderKey(vaultName, req.Provider, key, model)
	if err != nil {
		log.Printf("vee store key: %v", err)
		srv.addAuditEntry("vee.key.store_failed", fmt.Sprintf("provider=%s vault=%s err=%v", req.Provider, vaultName, err))
		httpError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	srv.addAuditEntry("vee.key.stored", fmt.Sprintf("provider=%s vault=%s source=%s changed=%v model=%s", req.Provider, vaultName, source, changed, model))
	// Freshly stored key is known-good: mark last-validated so the card
	// lights green immediately without a second probe.
	setLastValidated(req.Provider, "ok")
	// Drop any in-memory cache for this provider so the next op read
	// picks up the value the user just wrote (otherwise a recently-
	// cached old key would shadow the rotation for up to veeKeyCacheTTL).
	srv.veeCacheInvalidate(req.Provider)
	// And prime the cache with the value we already have in hand —
	// this avoids a fresh op read (and another Windows Hello prompt)
	// on the very next chat message.
	srv.veeCachePutKey(req.Provider, vaultName, key)
	if model != "" {
		srv.veeCachePutModel(req.Provider, vaultName, model)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"stored":         stored,
		"changed":        changed,
		"model":          model,
		"vault":          vaultName,
		"vault_location": fmt.Sprintf("op://%s/vee-%s-key/credential", vaultName, req.Provider),
	})
}

// handleVeeSettingsGet returns Vee-facing settings the UI needs to
// render provenance hints and the vault picker.
func (srv *Server) handleVeeSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"vee_vault_name":     srv.getVeeVaultName(),
		"default_vault_name": vault.DefaultVeeVaultName,
	})
}

// handleVeeSettingsPost accepts a new vault name. Blank resets to the
// default ("Vaultify"); any non-empty value is stored verbatim so the
// user can keep keys in "Personal" or a dedicated vault.
func (srv *Server) handleVeeSettingsPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VeeVaultName string `json:"vee_vault_name"`
	}
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	name := strings.TrimSpace(req.VeeVaultName)
	if err := srv.setVeeVaultName(name); err != nil {
		httpError(w, http.StatusInternalServerError, "save settings: %v", err)
		return
	}
	srv.addAuditEntry("vee.settings.vault_changed", fmt.Sprintf("vault=%s", srv.getVeeVaultName()))
	// Drop any previous last-validated rows since they referenced the
	// old vault's key.
	veeLastValidatedMu.Lock()
	veeLastValidated = map[string]veeValidationRecord{}
	veeLastValidatedMu.Unlock()
	// Same reasoning as the validation cache — stored secrets in the
	// per-server cache were keyed against the old vault. The cache
	// already self-checks the vault name, but explicit invalidation
	// keeps memory tidy.
	srv.veeCacheInvalidateAll()
	writeJSON(w, http.StatusOK, map[string]any{"vee_vault_name": srv.getVeeVaultName()})
}

func isOllamaRunning() bool {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get("http://localhost:11434/api/tags")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// --- Vee key/model cache --------------------------------------------
//
// Every `op read op://...` is a child process that, on Windows with
// "always require unlock" set, can pop a Windows Hello / 1Password
// authorize prompt — even when a session has just been authorized for
// a sibling secret. Without this cache, a single chat message paid for
// two op reads (credential + username/model), and the validate-stored-
// key burst paid for 2 × N providers in parallel — three providers
// times two reads = up to six popups for a single panel open. Caching
// the (key, model) pair for 5 minutes collapses everything past the
// first read into in-memory hits, which is what the user expected
// from "Vaultify is already connected to 1Password".
//
// Cache is invalidated when:
//   - the user stores a new key (StoreVeeProviderKey)
//   - the user changes the Vee vault name in settings
//   - the user signs out of 1Password (vault auth cache invalidate)

const veeKeyCacheTTL = 5 * time.Minute

type veeCachedSecret struct {
	key   string
	model string
	at    time.Time
	vault string // tracked so a vault rename mid-TTL invalidates correctly
}

func (srv *Server) veeCacheGet(provider, vaultName string) (key, model string, ok bool) {
	srv.veeKeyCacheMu.Lock()
	defer srv.veeKeyCacheMu.Unlock()
	e, found := srv.veeKeyCache[provider]
	if !found {
		return "", "", false
	}
	if e.vault != vaultName {
		return "", "", false
	}
	if time.Since(e.at) >= veeKeyCacheTTL {
		return "", "", false
	}
	return e.key, e.model, true
}

func (srv *Server) veeCachePutKey(provider, vaultName, key string) {
	srv.veeKeyCacheMu.Lock()
	defer srv.veeKeyCacheMu.Unlock()
	if srv.veeKeyCache == nil {
		srv.veeKeyCache = map[string]veeCachedSecret{}
	}
	prev := srv.veeKeyCache[provider]
	if prev.vault != vaultName {
		prev = veeCachedSecret{}
	}
	srv.veeKeyCache[provider] = veeCachedSecret{
		key:   key,
		model: prev.model,
		at:    time.Now(),
		vault: vaultName,
	}
}

func (srv *Server) veeCachePutModel(provider, vaultName, model string) {
	srv.veeKeyCacheMu.Lock()
	defer srv.veeKeyCacheMu.Unlock()
	if srv.veeKeyCache == nil {
		srv.veeKeyCache = map[string]veeCachedSecret{}
	}
	prev := srv.veeKeyCache[provider]
	if prev.vault != vaultName {
		prev = veeCachedSecret{}
	}
	srv.veeKeyCache[provider] = veeCachedSecret{
		key:   prev.key,
		model: model,
		at:    time.Now(),
		vault: vaultName,
	}
}

// veeCacheInvalidate forgets the cached secret for one provider so the
// next read goes to the vault. Called whenever the user stores a new
// key for that provider.
func (srv *Server) veeCacheInvalidate(provider string) {
	srv.veeKeyCacheMu.Lock()
	defer srv.veeKeyCacheMu.Unlock()
	delete(srv.veeKeyCache, provider)
}

// veeCacheInvalidateAll forgets every cached Vee secret. Called when
// the Vee vault name changes (so every cached entry is now wrong) and
// from sign-out flows.
func (srv *Server) veeCacheInvalidateAll() {
	srv.veeKeyCacheMu.Lock()
	defer srv.veeKeyCacheMu.Unlock()
	srv.veeKeyCache = map[string]veeCachedSecret{}
}

func (srv *Server) getVeeKey(provider string) string {
	vaultName := srv.getVeeVaultName()
	if k, _, ok := srv.veeCacheGet(provider, vaultName); ok && k != "" {
		return k
	}
	ref := fmt.Sprintf("op://%s/vee-%s-key/credential", vaultName, provider)
	v, err := srv.activeBackend().ReadSecret(ref)
	if err != nil || v == "" {
		srv.addAuditEntry("vee.key.read_failed", fmt.Sprintf("provider=%s ref=%s err=%v", provider, ref, err))
		return ""
	}
	srv.veeCachePutKey(provider, vaultName, v)
	return v
}

func (srv *Server) getVeeModel(provider string) string {
	vaultName := srv.getVeeVaultName()
	if _, m, ok := srv.veeCacheGet(provider, vaultName); ok && m != "" {
		return m
	}
	ref := fmt.Sprintf("op://%s/vee-%s-key/username", vaultName, provider)
	v, err := srv.activeBackend().ReadSecret(ref)
	if err != nil || v == "" {
		return ""
	}
	srv.veeCachePutModel(provider, vaultName, v)
	return v
}

// Provider-specific HTTP code lives in vee_providers.go. Everything
// below this point is Vee-adjacent helpers.

func stripJSONFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		lines := strings.SplitN(s, "\n", 2)
		if len(lines) == 2 {
			s = lines[1]
		}
		if i := strings.LastIndex(s, "```"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

type veeFpFinderRequest struct {
	SessionID string `json:"session_id"`
	Provider  string `json:"provider"`
}

type veeFpFinderResponse struct {
	LikelyFalsePositiveHashes []string `json:"likely_false_positive_hashes"`
	Reasoning                 string   `json:"reasoning"`
}

func (srv *Server) handleVeeFpFinder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !buildinfo.IsPro() {
		httpError(w, http.StatusForbidden, "Vee FP Finder is a Vaultify Pro feature.")
		return
	}
	var req veeFpFinderRequest
	if err := readRequestJSON(r, &req); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	sid := req.SessionID
	if sid == "" {
		srv.state.mu.Lock()
		sid = srv.state.SessionID
		srv.state.mu.Unlock()
	}
	if sid == "" {
		httpError(w, http.StatusBadRequest, "session_id required")
		return
	}
	if !session.IsValidID(sid) {
		httpError(w, http.StatusBadRequest, "invalid session id")
		return
	}

	var findings []scanner.Finding
	sess, err := srv.sessions.Get(sid)
	if err != nil {
		srv.state.mu.Lock()
		findings = make([]scanner.Finding, len(srv.state.Findings))
		copy(findings, srv.state.Findings)
		srv.state.mu.Unlock()
	} else {
		findings = sess.Findings
	}
	if len(findings) == 0 {
		httpError(w, http.StatusBadRequest, "no findings in session")
		return
	}

	type fpRow struct {
		H    string  `json:"h"`
		P    string  `json:"p"`
		S    string  `json:"s"`
		E    float64 `json:"e"`
		Path string  `json:"path"`
		Ln   int     `json:"ln"`
		L    string  `json:"layer,omitempty"`
		Prev string  `json:"prev"`
	}
	seen := map[string]scanner.Finding{}
	for _, f := range findings {
		if f.MatchSHA256 == "" {
			continue
		}
		if _, ok := seen[f.MatchSHA256]; !ok {
			seen[f.MatchSHA256] = f
		}
	}
	rows := make([]fpRow, 0, len(seen))
	for _, f := range seen {
		prev := f.RedactedPreview
		if len(prev) > 12 {
			prev = prev[:6] + "..." + prev[len(prev)-4:]
		}
		rows = append(rows, fpRow{
			H:    f.MatchSHA256,
			P:    f.PatternID,
			S:    f.Severity,
			E:    f.Entropy,
			Path: f.RelativePath,
			Ln:   f.LineNumber,
			L:    f.DetectionLayer,
			Prev: prev,
		})
	}
	max := 100
	if len(rows) > max {
		rows = rows[:max]
	}
	payload, _ := json.MarshalIndent(rows, "", "  ")

	system := `You are Vee, Vaultify's triage assistant. You receive ONLY redacted metadata about secret findings (no real secret values).
Your task: identify likely FALSE POSITIVES — e.g. cache paths, test fixtures, placeholder-looking previews, very low entropy with generic pattern names, SDK/browser profile paths, documentation examples.
Respond with STRICTLY valid JSON only — no markdown fences, no commentary outside JSON.
Shape: {"likely_false_positive_hashes":["64-char hex sha256..."],"reasoning":"brief UK English explanation"}`

	user := fmt.Sprintf("Findings metadata (unique by match hash):\n%s\n\nReturn JSON listing match_sha256 values (field h) that are likely false positives.", string(payload))

	providerID := req.Provider
	if providerID == "" {
		providerID = "gemini"
	}
	provider := ProviderByID(providerID)
	if provider == nil {
		httpError(w, http.StatusBadRequest, "unknown provider: %s", providerID)
		return
	}
	apiKey := srv.getVeeKey(providerID)
	if apiKey == "" && providerID != "ollama" {
		httpError(w, http.StatusBadRequest, "No %s API key in the configured Vee vault.", providerID)
		return
	}

	in := ChatInput{
		Model:        srv.getVeeModel(providerID),
		Key:          apiKey,
		SystemPrompt: system,
		UserMessage:  user,
	}
	// Use the non-streaming path: FP Finder needs the whole JSON blob
	// before it can parse. Context comes from the HTTP request so
	// cancelling the client aborts the upstream LLM call.
	text, perr := provider.Generate(r.Context(), in)
	if perr != nil {
		veeLog().Warn("fp_finder.error",
			slog.String("provider", perr.Provider),
			slog.Int("status", perr.Status),
			slog.String("category", string(perr.Category)),
			slog.String("message", truncateStr(perr.Message, 400)),
		)
		httpError(w, http.StatusBadGateway, "LLM %s (%s): %s", providerID, perr.Category, describeProviderError(perr))
		return
	}
	text = stripJSONFence(text)
	var out veeFpFinderResponse
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		raw := text
		if len(raw) > 300 {
			raw = raw[:300] + "..."
		}
		log.Printf("vee fp-finder: parse model JSON: %v; raw snippet: %s", err, raw)
		httpError(w, http.StatusInternalServerError, "model response could not be parsed")
		return
	}
	valid := map[string]bool{}
	for _, f := range seen {
		valid[f.MatchSHA256] = true
	}
	filtered := make([]string, 0, len(out.LikelyFalsePositiveHashes))
	for _, h := range out.LikelyFalsePositiveHashes {
		if valid[h] {
			filtered = append(filtered, h)
		}
	}
	out.LikelyFalsePositiveHashes = filtered
	writeJSON(w, http.StatusOK, out)
}

func init() {
	_ = log.Prefix
}
