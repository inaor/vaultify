package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// Phase 5: unified LLM provider layer.
//
// Before this, every provider had two copy-pasted functions — one for
// "stream" (which wasn't actually streaming — it read the full body
// then flushed once) and one for "generate block". That was four
// providers × two shapes = eight functions with subtly different
// timeouts, error handling, and silencing patterns.
//
// Now there's one ChatProvider interface, one shared *http.Client with
// a real timeout, one structured ProviderError, and real incremental
// streaming (OpenAI/Anthropic SSE, Gemini streamGenerateContent SSE,
// Ollama line-delimited JSON). Every Chat respects context cancellation
// so the UI can cut a long response off mid-stream.
// -----------------------------------------------------------------------------

// veeHTTPClient is the shared client for every provider call. A single
// timeout is preferable to per-function timeouts because it keeps the
// failure mode predictable: a provider that hangs dies after 60 s,
// period. Individual callers can still use shorter ctx deadlines.
var veeHTTPClient = &http.Client{Timeout: 60 * time.Second}

// ChatInput carries everything a provider needs to produce a completion.
type ChatInput struct {
	Model        string
	Key          string
	SystemPrompt string
	UserMessage  string
}

// ErrorCategory classifies provider failures so the UI can show an
// actionable message instead of a raw HTTP body.
type ErrorCategory string

const (
	ErrAuth       ErrorCategory = "auth"        // 401/403 — invalid or revoked key
	ErrRateLimit  ErrorCategory = "rate_limit"  // 429
	ErrQuota      ErrorCategory = "quota"       // 402 / 403 quota_exceeded bodies
	ErrNetwork    ErrorCategory = "network"     // connection refused, DNS, timeout
	ErrBadInput   ErrorCategory = "bad_input"   // 400 schema/model errors
	ErrProviderUp ErrorCategory = "backend"     // 5xx upstream
	ErrUnknown    ErrorCategory = "unknown"
)

// ProviderError is the structured failure we surface to callers.
type ProviderError struct {
	Provider string        `json:"provider"`
	Status   int           `json:"status,omitempty"`
	Category ErrorCategory `json:"category"`
	Message  string        `json:"message"`
}

func (e *ProviderError) Error() string {
	if e == nil {
		return "provider error"
	}
	return fmt.Sprintf("%s %s: %s", e.Provider, e.Category, e.Message)
}

// ChatProvider is the per-LLM integration. Chat streams to w (writes are
// flushed if the writer supports http.Flusher). Generate returns the
// full text at once; concrete providers may implement it by buffering
// Chat output but most upstreams have a non-stream endpoint so we use
// that directly for lower overhead.
type ChatProvider interface {
	ID() string
	DefaultModel() string
	Chat(ctx context.Context, in ChatInput, w io.Writer) (text string, perr *ProviderError)
	Generate(ctx context.Context, in ChatInput) (text string, perr *ProviderError)
}

// VeeProviders exposes the canonical provider registry. Package-level
// map is fine — providers are stateless and safe for concurrent use.
var veeProvidersRegistry = map[string]ChatProvider{
	"openai":    &openaiProvider{},
	"anthropic": &anthropicProvider{},
	"gemini":    &geminiProvider{},
	"ollama":    &ollamaProvider{},
}

func ProviderByID(id string) ChatProvider { return veeProvidersRegistry[id] }

// -----------------------------------------------------------------------------
// Helpers shared by every provider
// -----------------------------------------------------------------------------

// classifyHTTP maps an upstream status code to one of our categories.
func classifyHTTP(status int) ErrorCategory {
	switch {
	case status == 401 || status == 403:
		return ErrAuth
	case status == 402:
		return ErrQuota
	case status == 429:
		return ErrRateLimit
	case status == 400 || status == 404:
		return ErrBadInput
	case status >= 500:
		return ErrProviderUp
	default:
		return ErrUnknown
	}
}

func classifyNetwork(err error) ErrorCategory {
	if err == nil {
		return ErrUnknown
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrNetwork
	}
	return ErrNetwork
}

// tryFlush writes and flushes to w in one go when possible.
func writeFlush(w io.Writer, s string) error {
	if _, err := io.WriteString(w, s); err != nil {
		return err
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

// readSSE iterates `data: <json>` lines from an SSE stream, invoking fn
// for each. A line equal to `data: [DONE]` stops the loop (OpenAI style).
// Non-data lines (comments, `event:` frames) are skipped but the caller
// can implement framing-aware logic on top by reading raw lines instead.
// readSSE returns when the stream closes or ctx is cancelled.
func readSSE(ctx context.Context, r io.Reader, fn func(rawJSON []byte) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		if len(line) == 0 || !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 {
			continue
		}
		if bytes.Equal(payload, []byte("[DONE]")) {
			return nil
		}
		if err := fn(payload); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// readLineDelimitedJSON reads \n-delimited JSON objects (Ollama style).
func readLineDelimitedJSON(ctx context.Context, r io.Reader, fn func(rawJSON []byte) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// veeLog returns the subsystem logger for provider code.
func veeLog() *slog.Logger {
	return slog.Default().With(slog.String("subsystem", "vee"))
}

// postJSON builds a POST request with JSON body + headers.
func postJSON(ctx context.Context, url string, payload any, headers map[string]string) (*http.Request, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// readBody caps and trims a response body into a single error message.
func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return strings.TrimSpace(string(b))
}

// -----------------------------------------------------------------------------
// OpenAI (Chat Completions, SSE streaming)
// -----------------------------------------------------------------------------

type openaiProvider struct{}

func (p *openaiProvider) ID() string           { return "openai" }
func (p *openaiProvider) DefaultModel() string { return "gpt-4.1-mini" }

func (p *openaiProvider) openaiMessages(in ChatInput) []map[string]string {
	return []map[string]string{
		{"role": "system", "content": in.SystemPrompt},
		{"role": "user", "content": in.UserMessage},
	}
}

func (p *openaiProvider) model(in ChatInput) string {
	if in.Model == "" || in.Model == "default" {
		return p.DefaultModel()
	}
	return in.Model
}

func (p *openaiProvider) Chat(ctx context.Context, in ChatInput, w io.Writer) (string, *ProviderError) {
	req, err := postJSON(ctx, "https://api.openai.com/v1/chat/completions", map[string]any{
		"model":    p.model(in),
		"messages": p.openaiMessages(in),
		"stream":   true,
	}, map[string]string{
		"Authorization": "Bearer " + in.Key,
		"Accept":        "text/event-stream",
	})
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: err.Error()}
	}
	resp, err := veeHTTPClient.Do(req)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: classifyNetwork(err), Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body := readBody(resp)
		return "", &ProviderError{Provider: p.ID(), Status: resp.StatusCode, Category: classifyHTTP(resp.StatusCode), Message: body}
	}

	var buf strings.Builder
	sseErr := readSSE(ctx, resp.Body, func(payload []byte) error {
		var ev struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(payload, &ev); err != nil {
			return nil // tolerate keep-alives / parse hiccups mid-stream
		}
		if len(ev.Choices) == 0 || ev.Choices[0].Delta.Content == "" {
			return nil
		}
		chunk := ev.Choices[0].Delta.Content
		buf.WriteString(chunk)
		return writeFlush(w, chunk)
	})
	if sseErr != nil && !errors.Is(sseErr, context.Canceled) {
		return buf.String(), &ProviderError{Provider: p.ID(), Category: ErrNetwork, Message: sseErr.Error()}
	}
	return buf.String(), nil
}

func (p *openaiProvider) Generate(ctx context.Context, in ChatInput) (string, *ProviderError) {
	req, err := postJSON(ctx, "https://api.openai.com/v1/chat/completions", map[string]any{
		"model":    p.model(in),
		"messages": p.openaiMessages(in),
		"stream":   false,
	}, map[string]string{
		"Authorization": "Bearer " + in.Key,
	})
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: err.Error()}
	}
	resp, err := veeHTTPClient.Do(req)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: classifyNetwork(err), Message: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", &ProviderError{Provider: p.ID(), Status: resp.StatusCode, Category: classifyHTTP(resp.StatusCode), Message: strings.TrimSpace(string(body))}
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	_ = json.Unmarshal(body, &result)
	if len(result.Choices) == 0 {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: "empty choices"}
	}
	return result.Choices[0].Message.Content, nil
}

// -----------------------------------------------------------------------------
// Anthropic (Messages API, SSE streaming)
// -----------------------------------------------------------------------------

type anthropicProvider struct{}

func (p *anthropicProvider) ID() string           { return "anthropic" }
func (p *anthropicProvider) DefaultModel() string { return "claude-3-5-haiku-20241022" }

func (p *anthropicProvider) model(in ChatInput) string {
	if in.Model == "" || in.Model == "default" {
		return p.DefaultModel()
	}
	return in.Model
}

func (p *anthropicProvider) headers(in ChatInput) map[string]string {
	return map[string]string{
		"x-api-key":         in.Key,
		"anthropic-version": "2023-06-01",
	}
}

func (p *anthropicProvider) Chat(ctx context.Context, in ChatInput, w io.Writer) (string, *ProviderError) {
	req, err := postJSON(ctx, "https://api.anthropic.com/v1/messages", map[string]any{
		"model":      p.model(in),
		"max_tokens": 2048,
		"system":     in.SystemPrompt,
		"messages":   []map[string]string{{"role": "user", "content": in.UserMessage}},
		"stream":     true,
	}, p.headers(in))
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: err.Error()}
	}
	resp, err := veeHTTPClient.Do(req)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: classifyNetwork(err), Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body := readBody(resp)
		return "", &ProviderError{Provider: p.ID(), Status: resp.StatusCode, Category: classifyHTTP(resp.StatusCode), Message: body}
	}

	var buf strings.Builder
	sseErr := readSSE(ctx, resp.Body, func(payload []byte) error {
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal(payload, &ev); err != nil {
			return nil
		}
		if ev.Type != "content_block_delta" || ev.Delta.Text == "" {
			return nil
		}
		buf.WriteString(ev.Delta.Text)
		return writeFlush(w, ev.Delta.Text)
	})
	if sseErr != nil && !errors.Is(sseErr, context.Canceled) {
		return buf.String(), &ProviderError{Provider: p.ID(), Category: ErrNetwork, Message: sseErr.Error()}
	}
	return buf.String(), nil
}

func (p *anthropicProvider) Generate(ctx context.Context, in ChatInput) (string, *ProviderError) {
	req, err := postJSON(ctx, "https://api.anthropic.com/v1/messages", map[string]any{
		"model":      p.model(in),
		"max_tokens": 2048,
		"system":     in.SystemPrompt,
		"messages":   []map[string]string{{"role": "user", "content": in.UserMessage}},
	}, p.headers(in))
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: err.Error()}
	}
	resp, err := veeHTTPClient.Do(req)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: classifyNetwork(err), Message: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", &ProviderError{Provider: p.ID(), Status: resp.StatusCode, Category: classifyHTTP(resp.StatusCode), Message: strings.TrimSpace(string(body))}
	}
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(body, &result)
	if len(result.Content) == 0 {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: "empty content"}
	}
	return result.Content[0].Text, nil
}

// -----------------------------------------------------------------------------
// Gemini (streamGenerateContent SSE)
// -----------------------------------------------------------------------------

type geminiProvider struct{}

func (p *geminiProvider) ID() string           { return "gemini" }
func (p *geminiProvider) DefaultModel() string { return "gemini-2.0-flash" }

func (p *geminiProvider) model(in ChatInput) string {
	if in.Model == "" || in.Model == "default" {
		return p.DefaultModel()
	}
	return in.Model
}

func (p *geminiProvider) body(in ChatInput) map[string]any {
	return map[string]any{
		"system_instruction": map[string]any{"parts": []map[string]string{{"text": in.SystemPrompt}}},
		"contents":           []map[string]any{{"parts": []map[string]string{{"text": in.UserMessage}}}},
	}
}

func (p *geminiProvider) Chat(ctx context.Context, in ChatInput, w io.Writer) (string, *ProviderError) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:streamGenerateContent?alt=sse", p.model(in))
	req, err := postJSON(ctx, url, p.body(in), map[string]string{
		"x-goog-api-key": in.Key,
		"Accept":         "text/event-stream",
	})
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: err.Error()}
	}
	resp, err := veeHTTPClient.Do(req)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: classifyNetwork(err), Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body := readBody(resp)
		return "", &ProviderError{Provider: p.ID(), Status: resp.StatusCode, Category: classifyHTTP(resp.StatusCode), Message: body}
	}

	var buf strings.Builder
	sseErr := readSSE(ctx, resp.Body, func(payload []byte) error {
		var ev struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(payload, &ev); err != nil {
			return nil
		}
		if len(ev.Candidates) == 0 || len(ev.Candidates[0].Content.Parts) == 0 {
			return nil
		}
		chunk := ev.Candidates[0].Content.Parts[0].Text
		if chunk == "" {
			return nil
		}
		buf.WriteString(chunk)
		return writeFlush(w, chunk)
	})
	if sseErr != nil && !errors.Is(sseErr, context.Canceled) {
		return buf.String(), &ProviderError{Provider: p.ID(), Category: ErrNetwork, Message: sseErr.Error()}
	}
	return buf.String(), nil
}

func (p *geminiProvider) Generate(ctx context.Context, in ChatInput) (string, *ProviderError) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", p.model(in))
	req, err := postJSON(ctx, url, p.body(in), map[string]string{"x-goog-api-key": in.Key})
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: err.Error()}
	}
	resp, err := veeHTTPClient.Do(req)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: classifyNetwork(err), Message: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", &ProviderError{Provider: p.ID(), Status: resp.StatusCode, Category: classifyHTTP(resp.StatusCode), Message: strings.TrimSpace(string(body))}
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
	_ = json.Unmarshal(body, &result)
	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: "empty candidates"}
	}
	return result.Candidates[0].Content.Parts[0].Text, nil
}

// -----------------------------------------------------------------------------
// Ollama (line-delimited JSON stream at /api/generate)
// -----------------------------------------------------------------------------

type ollamaProvider struct{}

func (p *ollamaProvider) ID() string           { return "ollama" }
func (p *ollamaProvider) DefaultModel() string { return "llama3.2" }

func (p *ollamaProvider) model(in ChatInput) string {
	if in.Model == "" || in.Model == "default" {
		return p.DefaultModel()
	}
	return in.Model
}

func (p *ollamaProvider) Chat(ctx context.Context, in ChatInput, w io.Writer) (string, *ProviderError) {
	prompt := in.SystemPrompt + "\n\nUser: " + in.UserMessage + "\n\nAssistant:"
	req, err := postJSON(ctx, "http://localhost:11434/api/generate", map[string]any{
		"model":  p.model(in),
		"prompt": prompt,
		"stream": true,
	}, nil)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: err.Error()}
	}
	resp, err := veeHTTPClient.Do(req)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: classifyNetwork(err), Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body := readBody(resp)
		return "", &ProviderError{Provider: p.ID(), Status: resp.StatusCode, Category: classifyHTTP(resp.StatusCode), Message: body}
	}

	var buf strings.Builder
	lineErr := readLineDelimitedJSON(ctx, resp.Body, func(payload []byte) error {
		var ev struct {
			Response string `json:"response"`
			Done     bool   `json:"done"`
		}
		if err := json.Unmarshal(payload, &ev); err != nil {
			return nil
		}
		if ev.Response != "" {
			buf.WriteString(ev.Response)
			if err := writeFlush(w, ev.Response); err != nil {
				return err
			}
		}
		if ev.Done {
			return io.EOF
		}
		return nil
	})
	if lineErr != nil && !errors.Is(lineErr, io.EOF) && !errors.Is(lineErr, context.Canceled) {
		return buf.String(), &ProviderError{Provider: p.ID(), Category: ErrNetwork, Message: lineErr.Error()}
	}
	return buf.String(), nil
}

func (p *ollamaProvider) Generate(ctx context.Context, in ChatInput) (string, *ProviderError) {
	prompt := in.SystemPrompt + "\n\nUser: " + in.UserMessage + "\n\nAssistant (JSON only):"
	req, err := postJSON(ctx, "http://localhost:11434/api/generate", map[string]any{
		"model":  p.model(in),
		"prompt": prompt,
		"stream": false,
	}, nil)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: err.Error()}
	}
	resp, err := veeHTTPClient.Do(req)
	if err != nil {
		return "", &ProviderError{Provider: p.ID(), Category: classifyNetwork(err), Message: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", &ProviderError{Provider: p.ID(), Status: resp.StatusCode, Category: classifyHTTP(resp.StatusCode), Message: strings.TrimSpace(string(body))}
	}
	var result struct {
		Response string `json:"response"`
	}
	_ = json.Unmarshal(body, &result)
	if result.Response == "" {
		return "", &ProviderError{Provider: p.ID(), Category: ErrUnknown, Message: "empty response"}
	}
	return result.Response, nil
}
