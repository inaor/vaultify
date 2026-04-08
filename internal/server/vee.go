package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type veeChatRequest struct {
	SessionID string `json:"session_id"`
	Message   string `json:"message"`
	Provider  string `json:"provider"`
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
}

const veeSystemPromptTemplate = `You are Vee, Vaultify's security assistant. You speak British English, are concise, professional, and approachable.
You are analysing a credential scan for session %s.

FINDINGS (%d total, %d unique secrets):
%s

PATTERN SUMMARY:
%s

You help the user:
- Understand which findings are genuine risks vs false positives (e.g. test fixtures, example keys)
- Prioritise remediation (critical severity first)
- Suggest whether to Vaultify (store in vault), Remove from code, or Dismiss each finding
- Generate executive summaries for governance reporting
- Explain what each pattern type means in plain language

RULES:
- Never reveal actual secret values -- only use redacted previews
- Never access the filesystem or any data outside this session
- Only discuss findings from this session
- If asked about other data or sessions, decline politely
- Keep responses concise -- bullet points over paragraphs
- Use UK English spelling`

func (srv *Server) buildVeeContext(sessionID string) (string, error) {
	if sessionID == "" {
		srv.state.mu.Lock()
		sessionID = srv.state.SessionID
		srv.state.mu.Unlock()
	}
	if sessionID == "" {
		return "", fmt.Errorf("no active session")
	}

	s, err := srv.sessions.Get(sessionID)
	if err != nil {
		srv.state.mu.Lock()
		findings := srv.state.Findings
		srv.state.mu.Unlock()
		if len(findings) == 0 {
			return "", fmt.Errorf("session not found and no active scan")
		}
		patMap := map[string]int{}
		uniqueHashes := map[string]bool{}
		for _, f := range findings {
			patMap[f.PatternID]++
			uniqueHashes[f.MatchSHA256] = true
		}
		findingsJSON, _ := json.MarshalIndent(findings[:min(len(findings), 50)], "", "  ")
		patSummary := ""
		for k, v := range patMap {
			patSummary += fmt.Sprintf("  %s: %d\n", k, v)
		}
		return fmt.Sprintf(veeSystemPromptTemplate, sessionID, len(findings), len(uniqueHashes), string(findingsJSON), patSummary), nil
	}

	patMap := map[string]int{}
	uniqueHashes := map[string]bool{}
	for _, f := range s.Findings {
		patMap[f.PatternID]++
		uniqueHashes[f.MatchSHA256] = true
	}

	maxFindings := 50
	subset := s.Findings
	if len(subset) > maxFindings {
		subset = subset[:maxFindings]
	}
	findingsJSON, _ := json.MarshalIndent(subset, "", "  ")

	patSummary := ""
	for k, v := range patMap {
		patSummary += fmt.Sprintf("  %s: %d\n", k, v)
	}

	return fmt.Sprintf(veeSystemPromptTemplate, sessionID, len(s.Findings), len(uniqueHashes), string(findingsJSON), patSummary), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

const veeNoScanPrompt = `You are Vee, Vaultify's security assistant. You speak British English, are concise, professional, and approachable.
No scan has been run yet. You can:
- Explain what Vaultify does (scans for plaintext secrets, helps vault or remove them)
- Guide the user to click "Start Scan" on the Scan tab
- Answer general questions about secrets management, credential hygiene, and vault best practices
- Explain what each pattern type detects (AWS keys, GitHub tokens, Slack tokens, etc.)

Keep responses concise. Use UK English spelling.`

func (srv *Server) handleVeeChat(w http.ResponseWriter, r *http.Request) {
	var req veeChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	systemPrompt, err := srv.buildVeeContext(req.SessionID)
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

	switch provider {
	case "openai":
		responseText, callErr = callOpenAI(apiKey, systemPrompt, req.Message, w, flusher, canFlush)
	case "anthropic":
		responseText, callErr = callAnthropic(apiKey, systemPrompt, req.Message, w, flusher, canFlush)
	case "gemini":
		responseText, callErr = callGemini(apiKey, systemPrompt, req.Message, w, flusher, canFlush)
	case "ollama":
		responseText, callErr = callOllama(systemPrompt, req.Message, w, flusher, canFlush)
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
		{ID: "openai", Name: "OpenAI", NeedsKey: true, Model: "gpt-4.1-mini"},
		{ID: "anthropic", Name: "Anthropic", NeedsKey: true, Model: "claude-3-5-haiku"},
		{ID: "gemini", Name: "Gemini", NeedsKey: true, Model: "gemini-2.0-flash"},
		{ID: "ollama", Name: "Ollama", NeedsKey: false, Model: "llama3.2"},
	}

	checkVault := r.URL.Query().Get("check") == "1"
	for i := range providers {
		if providers[i].NeedsKey {
			if checkVault {
				key := srv.getVeeKey(providers[i].ID)
				providers[i].HasKey = key != ""
				providers[i].Available = providers[i].HasKey
			}
		} else {
			providers[i].Available = isOllamaRunning()
		}
	}

	writeJSON(w, http.StatusOK, providers)
}

func (srv *Server) handleVeeStoreKey(w http.ResponseWriter, r *http.Request) {
	var req veeKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	cmd := exec.Command(opPath, "item", "create", "--vault", "Vaultify", "--category", "API Credential", "--title", title, "credential="+req.Key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		existing := exec.Command(opPath, "item", "edit", title, "--vault", "Vaultify", "credential="+req.Key)
		out2, err2 := existing.CombinedOutput()
		if err2 != nil {
			httpError(w, http.StatusInternalServerError, "failed to store key: %s / %s", strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
			return
		}
		_ = out2
	}
	writeJSON(w, http.StatusOK, map[string]bool{"stored": true})
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

// --- LLM Provider Implementations ---

func callOpenAI(apiKey, systemPrompt, userMessage string, w http.ResponseWriter, flusher http.Flusher, canFlush bool) (string, error) {
	body := map[string]any{
		"model": "gpt-4.1-mini",
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

func callAnthropic(apiKey, systemPrompt, userMessage string, w http.ResponseWriter, flusher http.Flusher, canFlush bool) (string, error) {
	body := map[string]any{
		"model":      "claude-3-5-haiku-20241022",
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

func callGemini(apiKey, systemPrompt, userMessage string, w http.ResponseWriter, flusher http.Flusher, canFlush bool) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=%s", apiKey)
	body := map[string]any{
		"system_instruction": map[string]any{"parts": []map[string]string{{"text": systemPrompt}}},
		"contents":           []map[string]any{{"parts": []map[string]string{{"text": userMessage}}}},
	}
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")

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

func callOllama(systemPrompt, userMessage string, w http.ResponseWriter, flusher http.Flusher, canFlush bool) (string, error) {
	body := map[string]any{
		"model":  "llama3.2",
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
