package scanner

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type testCase struct {
	filename string
	content  string
	expected map[string]bool // pattern_id -> should match (true = TP, false = FP that should be filtered)
}

func generateTestCases() []testCase {
	return []testCase{
		// ============================================================
		// TRUE POSITIVES — real-shaped secrets in source-like files
		// ============================================================
		{
			filename: "project-alpha/.env",
			content: `# Production config
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SLACK_TOKEN=xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef1234
TELEGRAM_BOT=6784320159:AAHk9GZp3s7Xq2YcR1FdNm5BvWxKj4EXAMPLE
`,
			expected: map[string]bool{
				"aws_access_key_id": true,
				"slack_bot":         true,
				"telegram_bot":      true,
			},
		},
		{
			filename: "project-alpha/config.json",
			content: `{
  "openai_key": "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx1234567890",
  "anthropic_key": "sk-ant-apiAbCdEfGhIjKlMnOpQr",
  "github_pat": "ghp_12345678901234567890123456789012345678",
  "stripe_key": "sk_live_AbCdEfGhIjKlMnOpQrStUvWx12",
  "sendgrid_key": "SG.ABCDEFGHIJKLMNOPQRSTUV.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
}
`,
			expected: map[string]bool{
				"openai_project": true,
				"anthropic_api":  true,
				"gh_pat_classic": true,
				"stripe_secret":  true,
				"sendgrid":       true,
			},
		},
		{
			filename: "project-alpha/deploy.yaml",
			content: `apiVersion: v1
data:
  aws_temp_key: ASIAY3GMJOQQXK7EXAMPLE
  google_api_key: AIzaSyB3k7MN0pQxR2sT4uV5wX6yZ8a9bCdEfGh
  npm_token: npm_AbCdEfGhIjKlMnOpQrStUvWxYz12345678901234
  gitlab_pat: glpat-AbCdEfGhIjKlMnOpQrSt
  linear_key: lin_api_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCD
  mailgun_key: key-AbCdEfGhIjKlMnOpQrStUvWxYz123456
  twilio_sid: AC1234567890abcdef1234567890abcdef
`,
			expected: map[string]bool{
				"aws_temp_access_key_id": true,
				"google_api_key":         true,
				"npm_token":              true,
				"gitlab_pat":             true,
				"linear":                 true,
				"mailgun":                true,
				"twilio":                 true,
			},
		},
		{
			filename: "project-alpha/creds.py",
			content: `
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0PbnGcY5unA
-----END RSA PRIVATE KEY-----"""

SHOPIFY = "shpat_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
ATLASSIAN = "ATATT3xAbCdEfGhIjKlMnOpQrStUv"
DATABRICKS = "dapi1234567890abcdef1234567890abcdef"
PULUMI = "pulumi-1234567890abcdef1234567890abcdef12345678"
NOTION = "secret_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCDEF"
`,
			expected: map[string]bool{
				"private_key_block": true,
				"shopify_token":     true,
				"atlassian_api_token": true,
				"databricks":        true,
				"pulumi":            true,
				"notion":            true,
			},
		},

		// ============================================================
		// FALSE POSITIVES — should NOT be flagged
		// ============================================================
		{
			filename: "capcut-template.js",
			content: `// CapCut event tracking
var config = {
  eventMapping: {
    "59632001:__eventId__click_subscribe_btn_modal": true,
    "56054001:__eventId__page_show_subscription_mgr": true,
    "65481001:__eventId__click_upgrade_btn_commerce": true,
  },
  callbackHandler: "12345678:handleOnClickSubscribeButton__callback",
};
`,
			expected: map[string]bool{
				"telegram_bot": false,
			},
		},
		{
			filename: "project-beta/utils.js",
			content: `// Not real tokens
const key = "key-getApplicationConfigFromServer";
const id = "ACthisIsNotReallyATwilioAccountSid";
const sk = "SKthisIsNotReallyATwilioAuthKeySid";
function handleCallback() {
  const data = "dapithisisnotadatabrickstokenitsfake";
}
`,
			expected: map[string]bool{
				"mailgun":    false,
				"twilio":     false,
				"twilio_auth": false,
				"databricks": false,
			},
		},
		{
			filename: "project-beta/constants.ts",
			content: `// Non-secret constants with token-like shapes
export const CSS_CLASS = "sk-proj-loadingSpinnerClassName";
export const NPM_SCOPE = "npm_configPackageRegistryDefault";
`,
			expected: map[string]bool{
				"openai_project": false,
			},
		},
		{
			filename: "slack-false.env",
			content: `# Slack webhook that's actually a documentation example
WEBHOOK_EXAMPLE=https://hooks.slack.com/services/TEXAMPLE/BEXAMPLE/exampleExampleExample
`,
			expected: map[string]bool{
				"slack_webhook": true, // webhook URLs are always suspicious even in docs
			},
		},
		{
			filename: "Apollon/backend/app.py",
			content: `access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
`,
			expected: map[string]bool{
				"access_token_expires": false,
				"access_token":       false,
			},
		},
		{
			filename: ".config/secure_signin/op.env",
			content: `JIRA_API_TOKEN=REDACTED_BY_VAULTIFY - API Key/credential
OTHER_SECRET=op://DriverSeat/Jira/credential/password
`,
			expected: map[string]bool{
				"JIRA_API_TOKEN": false,
				"OTHER_SECRET":   false,
				PatternOpSecretRef: true,
			},
		},
	}
}

func TestScannerQuality(t *testing.T) {
	baseDir, err := os.MkdirTemp("", "vaultify-quality-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(baseDir)

	cases := generateTestCases()
	for _, tc := range cases {
		fp := filepath.Join(baseDir, filepath.FromSlash(tc.filename))
		if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(fp, []byte(tc.content), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	sc := NewScanner()

	totalTP := 0
	totalFP := 0
	caughtTP := 0
	filteredFP := 0
	missedTP := 0
	leakedFP := 0

	var details []string

	for _, tc := range cases {
		fp := filepath.Join(baseDir, filepath.FromSlash(tc.filename))
		findings := sc.scanFile(fp, baseDir)

		foundPatterns := map[string]string{}
		for _, f := range findings {
			foundPatterns[f.PatternID] = f.Value
		}

		for patID, shouldMatch := range tc.expected {
			if shouldMatch {
				totalTP++
				if _, ok := foundPatterns[patID]; ok {
					caughtTP++
					details = append(details, fmt.Sprintf("  ✓ TP  %-25s in %-35s CAUGHT", patID, tc.filename))
				} else {
					missedTP++
					details = append(details, fmt.Sprintf("  ✗ TP  %-25s in %-35s MISSED", patID, tc.filename))
				}
			} else {
				totalFP++
				if val, ok := foundPatterns[patID]; ok {
					leakedFP++
					h := sha256.Sum256([]byte(val))
					ent := shannonEntropy(val)
					details = append(details, fmt.Sprintf("  ✗ FP  %-25s in %-35s LEAKED (entropy=%.2f sha=%x...)", patID, tc.filename, ent, h[:4]))
				} else {
					filteredFP++
					details = append(details, fmt.Sprintf("  ✓ FP  %-25s in %-35s FILTERED", patID, tc.filename))
				}
			}
		}
	}

	t.Log("\n========== VAULTIFY SCANNER QUALITY REPORT ==========")
	for _, d := range details {
		t.Log(d)
	}
	t.Log("=====================================================")
	t.Logf("True Positives:  %d/%d caught  (%d missed)", caughtTP, totalTP, missedTP)
	t.Logf("False Positives: %d/%d filtered (%d leaked)", filteredFP, totalFP, leakedFP)

	tpRate := 0.0
	if totalTP > 0 {
		tpRate = float64(caughtTP) / float64(totalTP) * 100
	}
	fpRate := 0.0
	if totalFP > 0 {
		fpRate = float64(filteredFP) / float64(totalFP) * 100
	}
	t.Logf("Detection rate:  %.0f%%", tpRate)
	t.Logf("FP filter rate:  %.0f%%", fpRate)

	if missedTP > 0 {
		t.Errorf("FAILED: %d true positives were missed", missedTP)
	}
	if leakedFP > 0 {
		t.Errorf("FAILED: %d false positives leaked through", leakedFP)
	}
}

func TestSkipsLinesWithVaultifyRedactionMarker(t *testing.T) {
	baseDir := t.TempDir()
	fp := filepath.Join(baseDir, "AppData", "Local", "Microsoft", "Office", "SolutionPackages", "1cf18159", "PackageResources", "AppxBlockMap.xml")
	if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `<Block Hash="obMmytXAi4m60gLIu5Te4eV01lTHBpurEv/fNqtd0s8=" Size="398"/></File><File Name="OfflineFiles/index_woREDACTED_BY_VAULTIFY.html" Size="609" LfhSize="124">`
	if err := os.WriteFile(fp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sc := NewScanner()
	findings := sc.scanFile(fp, baseDir)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when line embeds REDACTED_BY_VAULTIFY, got %d (first: %+v)", len(findings), findings[0])
	}
}

func TestContextLayerSkippedInLowTrustPaths(t *testing.T) {
	baseDir := t.TempDir()
	cacheDir := filepath.Join(baseDir, "cache", "openclaw_repo")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(cacheDir, "config.ts")
	content := `const my_api_key = "sk-ant-api03AbCdEfGhIjKlMnOpQrStUvWxYz12345678901234";`
	if err := os.WriteFile(fp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sc := NewScanner()
	findings := sc.scanFile(fp, baseDir)
	for _, f := range findings {
		if f.DetectionLayer == "context" {
			t.Fatalf("context finding in cache path (should skip layer 2): %+v", f)
		}
	}
}

func TestEntropyValues(t *testing.T) {
	samples := []struct {
		label string
		val   string
	}{
		{"Real AWS Key", "AKIAIOSFODNN7EXAMPLE"},
		{"Real GitHub PAT", "REDACTED_BY_VAULTIFY"},
		{"Real Telegram Token", "6784320159:AAHk9GZp3s7Xq2YcR1FdNm5BvWxKj4EXAMPLE"},
		{"FP CapCut event", "59632001:__eventId__click_subscribe_btn_modal"},
		{"FP code identifier", "key-getApplicationConfigFromServer"},
		{"FP CSS class", "sk-proj-loadingSpinnerClassName"},
		{"FP Twilio-shaped", "ACthisIsNotReallyATwilioAccountSid"},
		{"Random hex 32", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
	}

	t.Log("\n========== ENTROPY VALUES ==========")
	for _, s := range samples {
		ent := shannonEntropy(s.val)
		code := looksLikeCode(s.val)
		t.Logf("  %.2f bits  code=%v  %s: %s", ent, code, s.label, s.val[:min(40, len(s.val))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
