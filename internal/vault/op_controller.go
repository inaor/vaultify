package vault

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OpState is the auth state machine for the 1Password CLI.
type OpState string

const (
	OpStateUnknown   OpState = "unknown"
	OpStateProbing   OpState = "probing"
	OpStateSignedIn  OpState = "signed_in"
	OpStateSignedOut OpState = "signed_out"
	OpStateOpening   OpState = "opening"
)

// OpTransition is emitted to subscribers whenever the state changes.
type OpTransition struct {
	State  OpState   `json:"state"`
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
}

// probeFuture coalesces concurrent probes behind a single subprocess call.
type probeFuture struct {
	done   chan struct{}
	result OpState
}

// OpSessionController owns every interaction with the 1Password CLI:
// the current auth state, the vault-list cache, a read/write mutex that
// parallelises reads while serialising writes, and a subscriber set for
// live transitions. There is exactly one instance per process.
type OpSessionController struct {
	// stateMu guards state, lastCheckAt, probeFuture, and the caches.
	stateMu     sync.Mutex
	state       OpState
	lastCheckAt time.Time
	probeFut    *probeFuture

	vaultListJSON []byte
	vaultListAt   time.Time
	lastProbeHint string
	lastProbeIssue OpProbeIssue

	// opMu is the RW gate for op subprocess calls.
	opMu sync.RWMutex
	// readSem bounds concurrent op reads so a bulk session probe cannot
	// blow up the 1Password CLI or the user's laptop.
	readSem chan struct{}

	// signinActive ensures only one BeginSignIn loop runs at a time.
	signinActive atomic.Bool

	// subscribers receive transitions for WS broadcast.
	subsMu    sync.Mutex
	subs      map[int]chan OpTransition
	nextSubID int
}

var (
	opControllerOnce sync.Once
	opControllerInst *OpSessionController
)

// OpProbeIssue classifies why an op vault-list probe failed.
type OpProbeIssue string

const (
	OpIssueNone                   OpProbeIssue = ""
	OpIssueCLIIntegrationDisabled OpProbeIssue = "cli_integration_disabled"
	OpIssueDesktopUnresponsive    OpProbeIssue = "desktop_unresponsive"
	OpIssueTimeout                OpProbeIssue = "timeout"
	OpIssueUnknown                OpProbeIssue = "unknown"
)

const (
	opReadSemSize        = 4
	opSessionTTLSignIn   = 3 * time.Minute
	opSessionTTLSignOut  = 12 * time.Second
	opVaultListCacheTTL2 = 2 * time.Minute
)

// OpController returns the process-wide controller singleton.
func OpController() *OpSessionController {
	opControllerOnce.Do(func() {
		opControllerInst = &OpSessionController{
			state:   OpStateUnknown,
			readSem: make(chan struct{}, opReadSemSize),
			subs:    make(map[int]chan OpTransition),
		}
	})
	return opControllerInst
}

// State returns the last known state.
func (c *OpSessionController) State() OpState {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.state == "" {
		return OpStateUnknown
	}
	return c.state
}

// SignedIn returns true when the controller's last known state is
// signed_in. This does not run a probe.
func (c *OpSessionController) SignedIn() bool {
	return c.State() == OpStateSignedIn
}

// LastCheckAt returns the moment the last probe completed (or zero if
// no probe has ever run).
func (c *OpSessionController) LastCheckAt() time.Time {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.lastCheckAt
}

// LastProbeHint returns a user-facing hint from the most recent failed probe.
func (c *OpSessionController) LastProbeHint() string {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.lastProbeHint
}

// LastProbeIssue returns a stable issue code for the most recent failed probe.
func (c *OpSessionController) LastProbeIssue() OpProbeIssue {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.lastProbeIssue
}

func (c *OpSessionController) setLastProbeHint(hint string) {
	c.stateMu.Lock()
	c.lastProbeHint = hint
	c.stateMu.Unlock()
}

func (c *OpSessionController) setLastProbeResult(hint string, issue OpProbeIssue) {
	c.stateMu.Lock()
	c.lastProbeHint = hint
	c.lastProbeIssue = issue
	c.stateMu.Unlock()
}

// InvalidateAuthCache resets state to Unknown and drops the vault-list
// cache. Subscribers get a transition if state changed.
func (c *OpSessionController) InvalidateAuthCache() {
	c.stateMu.Lock()
	prev := c.state
	c.state = OpStateUnknown
	c.lastCheckAt = time.Time{}
	c.vaultListJSON = nil
	c.vaultListAt = time.Time{}
	c.stateMu.Unlock()
	if prev != OpStateUnknown {
		c.broadcast(OpTransition{State: OpStateUnknown, Reason: "cache_invalidated", At: time.Now()})
	}
}

// CachedVaultListJSON returns a copy of the cached `op vault list`
// output when it is still fresh, else nil.
func (c *OpSessionController) CachedVaultListJSON() []byte {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if len(c.vaultListJSON) == 0 || time.Since(c.vaultListAt) >= opVaultListCacheTTL2 {
		return nil
	}
	out := make([]byte, len(c.vaultListJSON))
	copy(out, c.vaultListJSON)
	return out
}

func (c *OpSessionController) setVaultListCache(b []byte) {
	c.stateMu.Lock()
	if len(b) > 0 {
		c.vaultListJSON = append([]byte(nil), b...)
		c.vaultListAt = time.Now()
	} else {
		c.vaultListJSON = nil
		c.vaultListAt = time.Time{}
	}
	c.stateMu.Unlock()
}

// fresh reports whether we have a recent-enough observation to skip a
// fresh probe.
func (c *OpSessionController) freshLocked() bool {
	if c.lastCheckAt.IsZero() {
		return false
	}
	ttl := opSessionTTLSignOut
	if c.state == OpStateSignedIn {
		ttl = opSessionTTLSignIn
	}
	return time.Since(c.lastCheckAt) < ttl
}

// Probe returns the current state after honouring cache + coalescing.
// Setting force=true bypasses the TTL cache but still coalesces
// concurrent callers behind a single subprocess call.
func (c *OpSessionController) Probe(ctx context.Context, force bool) OpState {
	c.stateMu.Lock()
	if !force && c.freshLocked() {
		s := c.state
		c.stateMu.Unlock()
		return s
	}
	if c.probeFut != nil {
		f := c.probeFut
		c.stateMu.Unlock()
		select {
		case <-f.done:
			return f.result
		case <-ctx.Done():
			return OpStateUnknown
		}
	}
	f := &probeFuture{done: make(chan struct{})}
	c.probeFut = f
	// Only emit a Probing transition when the state actually changes to
	// avoid spamming subscribers during background refreshes.
	prev := c.state
	c.stateMu.Unlock()
	if prev != OpStateProbing {
		// Do not overwrite Opening with Probing while a signin loop is running.
		if prev != OpStateOpening {
			c.setState(OpStateProbing, "probe_started")
		}
	}

	go func() {
		result, _ := c.runProbeOnce(opVaultListTimeout)
		c.stateMu.Lock()
		f.result = result
		close(f.done)
		c.probeFut = nil
		c.lastCheckAt = time.Now()
		prevInner := c.state
		c.state = result
		c.stateMu.Unlock()
		if prevInner != result {
			c.broadcast(OpTransition{State: result, Reason: "probe_done", At: time.Now()})
		}
	}()

	select {
	case <-f.done:
		return f.result
	case <-ctx.Done():
		return OpStateUnknown
	}
}

// ProbeAsync kicks off a probe without blocking. Callers that only need
// the state to be published on WS should use this.
func (c *OpSessionController) ProbeAsync(force bool) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), opVaultListTimeout+2*time.Second)
		defer cancel()
		_ = c.Probe(ctx, force)
	}()
}

// runProbeOnce runs a single `op vault list` through the read path and
// updates the vault-list cache on success. It does not update state;
// Probe does that.
//
// timeout bounds the subprocess. Background probes use the short
// opVaultListTimeout (steady-state desktop responses are immediate);
// BeginSignIn passes the longer opSignInProbeTimeout so the human leg
// of an interactive unlock (Windows Hello / WAM → password → desktop
// wakes) is not killed mid-flow.
//
// The second return is the underlying op error (or nil on success).
// BeginSignIn inspects it to detect the "Desktop unresponsive" failure
// mode and bail out fast instead of polling for ~13 minutes; in normal
// path use of Probe(), nil is returned alongside SignedIn.
func (c *OpSessionController) runProbeOnce(timeout time.Duration) (OpState, *OpError) {
	if _, err := ResolveOpPath(); err != nil {
		return OpStateSignedOut, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, opErr := c.RunRead(ctx, "vault list (probe)", []string{"vault", "list", "--format=json"}, timeout)
	if opErr != nil || len(bytes.TrimSpace(out)) == 0 {
		c.setVaultListCache(nil)
		hint, issue := classifyOpProbeFailure(opErr)
		c.setLastProbeResult(hint, issue)
		// Map the queue-wait failure mode (where the read semaphore
		// kept us waiting until the ctx already expired, so the op
		// subprocess never ran) to the same `Timeout=true` shape the
		// real-subprocess timeout produces. BeginSignIn looks at
		// Timeout to count consecutive "Desktop unresponsive" probes;
		// without this, queue-wait failures showed `Duration=0s`
		// without `Timeout=true` and slipped past the bail-out logic.
		if opErr != nil && opErr.Duration == 0 && errors.Is(opErr.Err, context.DeadlineExceeded) {
			opErr.Timeout = true
		}
		return OpStateSignedOut, opErr
	}
	c.setLastProbeResult("", OpIssueNone)
	c.setVaultListCache(out)
	return OpStateSignedIn, nil
}

func classifyOpProbeFailure(opErr *OpError) (hint string, issue OpProbeIssue) {
	if opErr == nil {
		return "Unlock 1Password and ensure the CLI can access your account.", OpIssueUnknown
	}
	stderr := strings.ToLower(opErr.Stderr + " " + opErr.Error())
	switch {
	case strings.Contains(stderr, "no accounts configured"),
		strings.Contains(stderr, "integrate with 1password cli"),
		strings.Contains(stderr, "desktop app integration"):
		return "Enable “Integrate with 1Password CLI” in 1Password → Settings → Developer, then authorize Vaultify when prompted.", OpIssueCLIIntegrationDisabled
	case isDesktopUnresponsive(opErr):
		return "1Password is open but the CLI cannot reach it. Check Developer → CLI activity and confirm integration is enabled.", OpIssueDesktopUnresponsive
	case opErr.Timeout:
		return "Timed out waiting for 1Password. Unlock the app and retry.", OpIssueTimeout
	default:
		if opErr.Stderr != "" {
			return truncateOpHint(opErr.Stderr), OpIssueUnknown
		}
		return "Unlock 1Password and ensure the CLI can access your account.", OpIssueUnknown
	}
}

// classifyOpProbeHint is kept for callers that only need the message string.
func classifyOpProbeHint(opErr *OpError) string {
	h, _ := classifyOpProbeFailure(opErr)
	return h
}

func truncateOpHint(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	if len(s) > 180 {
		return s[:180] + "…"
	}
	return s
}

// isDesktopUnresponsive reports whether an op probe failure looks like
// the 1Password Desktop app being hung / not running / CLI integration
// disabled. Used by BeginSignIn to abort the polling loop early
// instead of burning ~16 s per probe waiting for the inevitable next
// timeout. The two signals are equivalent in practice — a context
// deadline OR the explicit "connecting to desktop app timed out" stderr.
func isDesktopUnresponsive(opErr *OpError) bool {
	if opErr == nil {
		return false
	}
	if opErr.Timeout {
		return true
	}
	return strings.Contains(opErr.Stderr, "connecting to desktop app")
}

// BeginSignIn starts a background goroutine that opens the 1Password
// desktop app and polls the CLI until the session unlocks or one of
// three exit conditions is reached. Transitions (opening → signed_in
// / signed_out, with a typed reason) are published to subscribers.
// Callers return immediately.
//
// Exit conditions:
//
//  1. SignedIn detected      → reason="unlock_detected"
//  2. Desktop is unresponsive across maxConsecutiveTimeouts probes
//                            → reason="desktop_unresponsive"
//  3. Total wall clock exceeds signinTotalBudget OR maxAttempts probed
//                            → reason="signin_timeout"
//
// Why the early-bail on (2): when 1Password Desktop is hung or has CLI
// integration disabled, every probe blocks for the full 15 s timeout.
// The original loop happily ran 48 of those for ~13 min, spawning a
// child `op` process each time and burning CPU + RAM. Three consecutive
// timeouts is enough to be confident the user needs manual recovery
// (open + unlock + enable CLI integration).
func (c *OpSessionController) BeginSignIn() {
	if !c.signinActive.CompareAndSwap(false, true) {
		return
	}
	c.setState(OpStateOpening, "user_requested_signin")

	go func() {
		defer c.signinActive.Store(false)
		logger := getLogger().With(slog.String("subsystem", "op_controller"))
		logger.Info("signin.begin")
		tryOpenOnePasswordDesktop()

		const (
			maxAttempts            = 48
			between                = 1100 * time.Millisecond
			signinTotalBudget      = 100 * time.Second
			// 2 × 45 s ≈ the wallclock budget. With the longer
			// per-probe timeout (opSignInProbeTimeout), counting
			// three consecutive timeouts before bailing would push
			// us past the budget and just trip the wallclock exit
			// instead, so two is enough.
			maxConsecutiveTimeouts = 2
		)
		started := time.Now()
		consecutiveTimeouts := 0

		for attempt := 0; attempt < maxAttempts; attempt++ {
			if time.Since(started) > signinTotalBudget {
				c.failSignIn(logger, "signin_timeout_wallclock", attempt)
				return
			}
			// The fast 1.1 s `between` only makes sense after a *fast*
			// probe (Desktop responsive, just not unlocked yet). After
			// a slow probe we already burned ~45 s; sleeping more just
			// wastes the user's time.
			if attempt > 0 && consecutiveTimeouts == 0 {
				time.Sleep(between)
			}

			st, opErr := c.runProbeOnce(opSignInProbeTimeout)
			if st == OpStateSignedIn {
				c.stateMu.Lock()
				c.lastCheckAt = time.Now()
				c.state = OpStateSignedIn
				c.stateMu.Unlock()
				logger.Info("signin.success", slog.Int("attempts", attempt+1))
				c.broadcast(OpTransition{State: OpStateSignedIn, Reason: "unlock_detected", At: time.Now()})
				return
			}
			if isDesktopUnresponsive(opErr) {
				consecutiveTimeouts++
				if consecutiveTimeouts >= maxConsecutiveTimeouts {
					c.failSignIn(logger, "desktop_unresponsive", attempt+1)
					return
				}
			} else {
				consecutiveTimeouts = 0
			}
		}
		c.failSignIn(logger, "signin_timeout", maxAttempts)
	}()
}

// failSignIn finalises a failed signin with a typed reason and
// publishes the transition. Centralised so all three exit paths (wall
// clock, max attempts, desktop unresponsive) emit the same audit shape.
func (c *OpSessionController) failSignIn(logger *slog.Logger, reason string, attempts int) {
	c.stateMu.Lock()
	c.lastCheckAt = time.Now()
	c.state = OpStateSignedOut
	c.stateMu.Unlock()
	logger.Warn("signin.failed", slog.String("reason", reason), slog.Int("attempts", attempts))
	c.broadcast(OpTransition{State: OpStateSignedOut, Reason: reason, At: time.Now()})
}

// SigninActive reports whether a BeginSignIn loop is currently running.
func (c *OpSessionController) SigninActive() bool {
	return c.signinActive.Load()
}

// RunRead executes a read-style op subprocess call. Multiple reads may
// run in parallel up to opReadSemSize; readers wait for any in-flight
// write to complete. Timeout bounds the subprocess.
func (c *OpSessionController) RunRead(ctx context.Context, opName string, args []string, timeout time.Duration) ([]byte, *OpError) {
	opPath, err := ResolveOpPath()
	if err != nil {
		return nil, &OpError{Op: opName, Err: errors.New("op CLI not found")}
	}
	c.opMu.RLock()
	defer c.opMu.RUnlock()
	select {
	case c.readSem <- struct{}{}:
		defer func() { <-c.readSem }()
	case <-ctx.Done():
		return nil, &OpError{Op: opName, Timeout: true, Err: ctx.Err()}
	}
	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return RunOp(subCtx, opPath, opName, args)
}

// RunWrite executes a write-style op subprocess call exclusively. No
// readers and no other writers run concurrently.
func (c *OpSessionController) RunWrite(ctx context.Context, opName string, args []string, timeout time.Duration) ([]byte, *OpError) {
	opPath, err := ResolveOpPath()
	if err != nil {
		return nil, &OpError{Op: opName, Err: errors.New("op CLI not found")}
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return RunOp(subCtx, opPath, opName, args)
}

// Subscribe returns a channel that receives future transitions and a
// cancel function. Slow subscribers miss messages instead of blocking.
func (c *OpSessionController) Subscribe() (<-chan OpTransition, func()) {
	c.subsMu.Lock()
	id := c.nextSubID
	c.nextSubID++
	ch := make(chan OpTransition, 16)
	c.subs[id] = ch
	c.subsMu.Unlock()
	return ch, func() {
		c.subsMu.Lock()
		if existing, ok := c.subs[id]; ok {
			delete(c.subs, id)
			close(existing)
		}
		c.subsMu.Unlock()
	}
}

func (c *OpSessionController) broadcast(t OpTransition) {
	c.subsMu.Lock()
	for _, ch := range c.subs {
		select {
		case ch <- t:
		default:
		}
	}
	c.subsMu.Unlock()
}

func (c *OpSessionController) setState(next OpState, reason string) {
	c.stateMu.Lock()
	prev := c.state
	c.state = next
	c.stateMu.Unlock()
	if prev != next {
		c.broadcast(OpTransition{State: next, Reason: reason, At: time.Now()})
	}
}
