package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/session"
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

type veeProviderStatus struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	NeedsKey  bool   `json:"needs_key"`
	HasKey    bool   `json:"has_key"`
	Available bool   `json:"available"`
	Model     string `json:"model"`
}

type veeKeyRequest struct {
	Provider string `json:"provider"`
	Key      string `json:"key"`
	Model    string `json:"model"`
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

	provider := req.Provider
	if provider == "" {
		provider = "openai"
	}

	apiKey := srv.getVeeKey(provider)
	if apiKey == "" && provider != "ollama" {
		httpError(w, http.StatusBadRequest, "No API key found for %s. Store it in your Vaultify vault first.", provider)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, canFlush := w.(http.Flusher)

	var responseText string
	var callErr error

	model := srv.getVeeModel(provider)
	switch provider {
	case "openai":
		if model == "" || model == "default" { model = "gpt-4.1-mini" }
		responseText, callErr = callOpenAI(apiKey, model, systemPrompt, req.Message, w, flusher, canFlush)
	case "anthropic":
		if model == "" || model == "default" { model = "claude-3-5-haiku-20241022" }
		responseText, callErr = callAnthropic(apiKey, model, systemPrompt, req.Message, w, flusher, canFlush)
	case "gemini":
		if model == "" || model == "default" { model = "gemini-2.0-flash" }
		responseText, callErr = callGemini(apiKey, model, systemPrompt, req.Message, w, flusher, canFlush)
	case "ollama":
		if model == "" || model == "default" { model = "llama3.2" }
		responseText, callErr = callOllama(model, systemPrompt, req.Message, w, flusher, canFlush)
	default:
		httpError(w, http.StatusBadRequest, "unknown provider: %s", provider)
		return
	}

	if callErr != nil {
		if responseText == "" {
			w.Write([]byte("\n\n[Error: " + callErr.Error() + "]"))
		}
	}
	_ = responseText
}

func (srv *Server) handleVeeProviders(w http.ResponseWriter, r *http.Request) {
	providers := []veeProviderStatus{
		{ID: "openai", Name: "GPT", NeedsKey: true},
		{ID: "anthropic", Name: "Claude", NeedsKey: true},
		{ID: "gemini", Name: "Gemini", NeedsKey: true},
		{ID: "ollama", Name: "Ollama", NeedsKey: false},
	}

	checkVault := r.URL.Query().Get("check") == "1"
	for i := range providers {
		if providers[i].NeedsKey {
			if checkVault {
				key := srv.getVeeKey(providers[i].ID)
				providers[i].HasKey = key != ""
				providers[i].Available = providers[i].HasKey
				if providers[i].HasKey {
					providers[i].Model = srv.getVeeModel(providers[i].ID)
				}
			}
		} else {
			providers[i].Available = isOllamaRunning()
		}
	}

	writeJSON(w, http.StatusOK, providers)
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

	var models []string
	switch req.Provider {
	case "openai":
		httpReq, _ := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
		httpReq.Header.Set("Authorization", "Bearer "+req.Key)
		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil || resp.StatusCode != 200 {
			httpError(w, http.StatusBadRequest, "Invalid API key or cannot reach OpenAI")
			return
		}
		defer resp.Body.Close()
		var result struct {
			Data []struct{ ID string `json:"id"` } `json:"data"`
		}
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &result)
		for _, m := range result.Data {
			if strings.Contains(m.ID, "gpt") {
				models = append(models, m.ID)
			}
		}
		sort.Strings(models)
	case "anthropic":
		models = []string{"claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-3-5-sonnet-20241022"}
	case "gemini":
		models = []string{"gemini-2.0-flash", "gemini-2.5-flash-preview-05-20", "gemini-2.5-pro-preview-05-06"}
	case "ollama":
		resp, err := http.Get("http://localhost:11434/api/tags")
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			var result struct {
				Models []struct{ Name string `json:"name"` } `json:"models"`
			}
			body, _ := io.ReadAll(resp.Body)
			json.Unmarshal(body, &result)
			for _, m := range result.Models {
				models = append(models, m.Name)
			}
		}
	}
	if models == nil {
		models = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": len(models) > 0, "models": models})
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
	if req.Provider == "" || req.Key == "" {
		httpError(w, http.StatusBadRequest, "provider and key required")
		return
	}

	opPath, err := exec.LookPath("op")
	if err != nil {
		httpError(w, http.StatusBadRequest, "1Password CLI not found")
		return
	}

	ensureVaultExists("Vaultify")
	title := fmt.Sprintf("vee-%s-key", req.Provider)
	model := req.Model
	if model == "" {
		model = "default"
	}
	cmd := exec.Command(opPath, "item", "create", "--vault", "Vaultify", "--category", "API Credential", "--title", title, "credential="+req.Key, "username="+model)
	out, err := cmd.CombinedOutput()
	if err != nil {
		existing := exec.Command(opPath, "item", "edit", title, "--vault", "Vaultify", "credential="+req.Key, "username="+model)
		out2, err2 := existing.CombinedOutput()
		if err2 != nil {
			log.Printf("vee store key: create err=%v out=%s edit err=%v out2=%s", err, strings.TrimSpace(string(out)), err2, strings.TrimSpace(string(out2)))
			httpError(w, http.StatusInternalServerError, "failed to store key in vault")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"stored": true, "model": model})
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

func (srv *Server) getVeeKey(provider string) string {
	opPath, err := exec.LookPath("op")
	if err != nil {
		return ""
	}
	ref := fmt.Sprintf("op://Vaultify/vee-%s-key/credential", provider)
	cmd := exec.Command(opPath, "read", ref)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (srv *Server) getVeeModel(provider string) string {
	opPath, err := exec.LookPath("op")
	if err != nil {
		return ""
	}
	ref := fmt.Sprintf("op://Vaultify/vee-%s-key/username", provider)
	cmd := exec.Command(opPath, "read", ref)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// --- LLM Provider Implementations ---

func callOpenAI(apiKey, model, systemPrompt, userMessage string, w http.ResponseWriter, flusher http.Flusher, canFlush bool) (string, error) {
	body := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userMessage},
		},
		"stream": false,
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OpenAI request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("OpenAI error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Choices) > 0 {
		text := result.Choices[0].Message.Content
		w.Write([]byte(text))
		if canFlush {
			flusher.Flush()
		}
		return text, nil
	}
	return "", fmt.Errorf("no response from OpenAI")
}

func callAnthropic(apiKey, model, systemPrompt, userMessage string, w http.ResponseWriter, flusher http.Flusher, canFlush bool) (string, error) {
	body := map[string]any{
		"model":      model,
		"max_tokens": 2048,
		"system":     systemPrompt,
		"messages":   []map[string]string{{"role": "user", "content": userMessage}},
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Anthropic request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Anthropic error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Content) > 0 {
		text := result.Content[0].Text
		w.Write([]byte(text))
		if canFlush {
			flusher.Flush()
		}
		return text, nil
	}
	return "", fmt.Errorf("no response from Anthropic")
}

func callGemini(apiKey, model, systemPrompt, userMessage string, w http.ResponseWriter, flusher http.Flusher, canFlush bool) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", model)
	body := map[string]any{
		"system_instruction": map[string]any{"parts": []map[string]string{{"text": systemPrompt}}},
		"contents":           []map[string]any{{"parts": []map[string]string{{"text": userMessage}}}},
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Gemini request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Gemini error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Candidates) > 0 && len(result.Candidates[0].Content.Parts) > 0 {
		text := result.Candidates[0].Content.Parts[0].Text
		w.Write([]byte(text))
		if canFlush {
			flusher.Flush()
		}
		return text, nil
	}
	return "", fmt.Errorf("no response from Gemini")
}

// --- Non-streaming LLM calls (for FP finder etc.) ---

func openaiGenerateBlock(apiKey, model, systemPrompt, userMessage string) (string, error) {
	if model == "" || model == "default" {
		model = "gpt-4.1-mini"
	}
	body := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userMessage},
		},
		"stream": false,
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("OpenAI error %d: %s", resp.StatusCode, string(respBody))
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Choices) > 0 {
		return result.Choices[0].Message.Content, nil
	}
	return "", fmt.Errorf("no response from OpenAI")
}

func anthropicGenerateBlock(apiKey, model, systemPrompt, userMessage string) (string, error) {
	if model == "" || model == "default" {
		model = "claude-3-5-haiku-20241022"
	}
	body := map[string]any{
		"model":      model,
		"max_tokens": 2048,
		"system":     systemPrompt,
		"messages":   []map[string]string{{"role": "user", "content": userMessage}},
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Anthropic error %d: %s", resp.StatusCode, string(respBody))
	}
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Content) > 0 {
		return result.Content[0].Text, nil
	}
	return "", fmt.Errorf("no response from Anthropic")
}

func geminiGenerateBlock(apiKey, model, systemPrompt, userMessage string) (string, error) {
	if model == "" || model == "default" {
		model = "gemini-2.0-flash"
	}
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", model)
	body := map[string]any{
		"system_instruction": map[string]any{"parts": []map[string]string{{"text": systemPrompt}}},
		"contents":           []map[string]any{{"parts": []map[string]string{{"text": userMessage}}}},
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Gemini error %d: %s", resp.StatusCode, string(respBody))
	}
	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	json.Unmarshal(respBody, &result)
	if len(result.Candidates) > 0 && len(result.Candidates[0].Content.Parts) > 0 {
		return result.Candidates[0].Content.Parts[0].Text, nil
	}
	return "", fmt.Errorf("no response from Gemini")
}

func ollamaGenerateBlock(model, systemPrompt, userMessage string) (string, error) {
	if model == "" || model == "default" {
		model = "llama3.2"
	}
	body := map[string]any{
		"model":  model,
		"prompt": systemPrompt + "\n\nUser: " + userMessage + "\n\nAssistant (JSON only):",
		"stream": false,
	}
	data, _ := json.Marshal(body)
	resp, err := http.Post("http://localhost:11434/api/generate", "application/json", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result struct {
		Response string `json:"response"`
	}
	json.Unmarshal(respBody, &result)
	if result.Response != "" {
		return result.Response, nil
	}
	return "", fmt.Errorf("no response from Ollama")
}

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

	provider := req.Provider
	if provider == "" {
		provider = "gemini"
	}
	model := srv.getVeeModel(provider)
	apiKey := srv.getVeeKey(provider)

	var text string
	var callErr error
	switch provider {
	case "openai":
		if apiKey == "" {
			httpError(w, http.StatusBadRequest, "No OpenAI API key in vault (vee-openai-key)")
			return
		}
		text, callErr = openaiGenerateBlock(apiKey, model, system, user)
	case "anthropic":
		if apiKey == "" {
			httpError(w, http.StatusBadRequest, "No Anthropic API key in vault")
			return
		}
		text, callErr = anthropicGenerateBlock(apiKey, model, system, user)
	case "gemini":
		if apiKey == "" {
			httpError(w, http.StatusBadRequest, "No Gemini API key in vault")
			return
		}
		text, callErr = geminiGenerateBlock(apiKey, model, system, user)
	case "ollama":
		text, callErr = ollamaGenerateBlock(model, system, user)
	default:
		httpError(w, http.StatusBadRequest, "unknown provider: %s", provider)
		return
	}
	if callErr != nil {
		httpError(w, http.StatusInternalServerError, "LLM: %v", callErr)
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

func callOllama(model, systemPrompt, userMessage string, w http.ResponseWriter, flusher http.Flusher, canFlush bool) (string, error) {
	body := map[string]any{
		"model":  model,
		"prompt": systemPrompt + "\n\nUser: " + userMessage + "\n\nVee:",
		"stream": false,
	}
	data, _ := json.Marshal(body)
	resp, err := http.Post("http://localhost:11434/api/generate", "application/json", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("Ollama not reachable: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result struct {
		Response string `json:"response"`
	}
	json.Unmarshal(respBody, &result)
	if result.Response != "" {
		w.Write([]byte(result.Response))
		if canFlush {
			flusher.Flush()
		}
		return result.Response, nil
	}
	return "", fmt.Errorf("no response from Ollama")
}

func init() {
	_ = log.Prefix
}
