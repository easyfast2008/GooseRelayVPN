package carrier

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// echoServer decodes the incoming batch, echoes each frame's payload back
// (with the SYN bit cleared and seq reset per session), and returns it.
func echoServer(t *testing.T, aead *frame.Crypto) (*httptest.Server, *int) {
	t.Helper()
	var hits int
	var mu sync.Mutex
	rxSeqBySession := map[[frame.SessionIDLen]byte]uint64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Errorf("server decode: %v", err)
			w.WriteHeader(500)
			return
		}
		var out []*frame.Frame
		mu.Lock()
		for _, f := range in {
			seq := rxSeqBySession[f.SessionID]
			rxSeqBySession[f.SessionID] = seq + 1
			out = append(out, &frame.Frame{
				SessionID: f.SessionID,
				Seq:       seq,
				Payload:   f.Payload,
			})
		}
		mu.Unlock()
		respBody, _ := frame.EncodeBatch(aead, out)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(respBody)
	}))
	return srv, &hits
}

func TestCarrier_RoundTripEcho(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv, _ := echoServer(t, aead)
	defer srv.Close()

	c, err := New(Config{
		ScriptURLs: []string{srv.URL},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	s := c.NewSession("example.com:80")
	s.EnqueueTx([]byte("hello"))

	// Read the echoed payload from the session's RxChan.
	select {
	case got := <-s.RxChan:
		if string(got) != "hello" {
			t.Fatalf("got %q want %q", got, "hello")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for echoed payload")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

func TestCarrier_UnknownSessionFramesDropped(t *testing.T) {
	aead, _ := frame.NewCryptoFromHexKey(testKeyHex)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always reply with one frame for an unknown session ID.
		var unknown [frame.SessionIDLen]byte
		for i := range unknown {
			unknown[i] = 0xEE
		}
		body, _ := frame.EncodeBatch(aead, []*frame.Frame{
			{SessionID: unknown, Seq: 0, Payload: []byte("ghost")},
		})
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	// Just let it run a couple of poll cycles. A panic / data race here is
	// the failure mode; the assertion is "doesn't crash."
	time.Sleep(200 * time.Millisecond)
}

func TestCarrier_PollOnceDropsNonBatchPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!doctype html><html><body>quota exceeded</body></html>"))
	}))
	defer srv.Close()

	c, err := New(Config{ScriptURLs: []string{srv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.httpClients = []*http.Client{srv.Client()}

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("expected no work for non-batch relay payload")
	}
}

func TestIsLikelyNonBatchRelayPayload(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{name: "html", in: []byte("<html>oops</html>"), want: true},
		{name: "doctype", in: []byte("<!DOCTYPE html>"), want: true},
		{name: "json", in: []byte(`{"e":"quota"}`), want: true},
		{name: "http", in: []byte("HTTP/1.1 502 Bad Gateway"), want: true},
		{name: "base64ish", in: []byte("QUJDRA=="), want: false},
		{name: "empty", in: []byte(" \r\n\t "), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLikelyNonBatchRelayPayload(tc.in); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestCarrier_FailsOverToHealthyScriptURLWithoutTxLoss(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("quota"))
	}))
	defer badSrv.Close()

	goodSrv, _ := echoServer(t, aead)
	defer goodSrv.Close()

	c, err := New(Config{ScriptURLs: []string{badSrv.URL, goodSrv.URL}, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	s := c.NewSession("example.com:80")
	s.EnqueueTx([]byte("hello-failover"))

	select {
	case got := <-s.RxChan:
		if string(got) != "hello-failover" {
			t.Fatalf("got %q want %q", got, "hello-failover")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for failover response")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

// TestCarrier_AllEndpointsBlacklistedQuiesces verifies the production
// regression fix: when every endpoint is currently blacklisted,
// pickRelayEndpoint returns -1 and pollOnce bails without burning a poll.
// Without this, the client spun in a tight loop polling blacklisted
// endpoints, every fail rolling the deadline forward another hour and
// pinning both endpoints at the max TTL indefinitely.
func TestCarrier_AllEndpointsBlacklistedQuiesces(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"https://example.invalid/a", "https://example.invalid/b"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	c.endpointMu.Lock()
	for i := range c.endpoints {
		c.endpoints[i].blacklistedTill = time.Now().Add(5 * time.Minute)
		c.endpoints[i].failCount = 8
	}
	c.endpointMu.Unlock()

	idx, url, eligible := c.pickRelayEndpointWithEligibility()
	if idx >= 0 || url != "" || eligible != 0 {
		t.Fatalf("expected (-1, \"\", 0) when all blacklisted, got (%d, %q, %d)", idx, url, eligible)
	}

	if didWork := c.pollOnce(context.Background()); didWork {
		t.Fatal("expected pollOnce to return false when all endpoints blacklisted")
	}

	if at := c.earliestEligibleAt(); at.IsZero() {
		t.Fatal("earliestEligibleAt should be non-zero when all blacklisted")
	}
}

// TestCarrier_BlacklistMonotonic verifies markEndpointFailure does NOT
// roll a steady deadline forward by another full TTL on every failure —
// the bug that pinned both endpoints at the max blacklist indefinitely
// under sustained throttle.
func TestCarrier_BlacklistMonotonic(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"https://example.invalid/a"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	c.endpointMu.Lock()
	c.endpoints[0].failCount = 7
	c.endpointMu.Unlock()

	c.markEndpointFailure(0)
	c.endpointMu.Lock()
	first := c.endpoints[0].blacklistedTill
	c.endpointMu.Unlock()

	time.Sleep(2 * time.Millisecond)
	c.markEndpointFailure(0)
	c.endpointMu.Lock()
	second := c.endpoints[0].blacklistedTill
	c.endpointMu.Unlock()

	delta := second.Sub(first)
	if delta > 50*time.Millisecond {
		t.Fatalf("blacklist deadline jumped %v on second failure (should be monotonic & bounded by elapsed time)", delta)
	}
}

// TestCarrier_BlacklistMaxTTLReduced ensures the cap is short enough that
// transient throttles recover within minutes, not hours.
func TestCarrier_BlacklistMaxTTLReduced(t *testing.T) {
	if endpointBlacklistMaxTTL > 10*time.Minute {
		t.Fatalf("endpointBlacklistMaxTTL=%s; should be ≤10min so transient throttles recover quickly", endpointBlacklistMaxTTL)
	}
	for fc := 1; fc <= 20; fc++ {
		ttl := endpointBlacklistTTL(fc)
		if ttl > endpointBlacklistMaxTTL {
			t.Fatalf("failCount=%d ttl=%s exceeds cap %s", fc, ttl, endpointBlacklistMaxTTL)
		}
	}
}

// TestCarrier_RetryAlternateOnlyWhenEligible verifies maxAttempts is
// pinned at 1 when only a single endpoint is eligible, even if the
// endpoint list has multiple URLs. Retrying onto a blacklisted alternate
// just compounds the cascade.
func TestCarrier_RetryAlternateOnlyWhenEligible(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"https://example.invalid/a", "https://example.invalid/b"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	// Blacklist endpoint 1; endpoint 0 is healthy.
	c.endpointMu.Lock()
	c.endpoints[1].blacklistedTill = time.Now().Add(5 * time.Minute)
	c.endpoints[1].failCount = 8
	c.endpointMu.Unlock()

	idx, url, eligible := c.pickRelayEndpointWithEligibility()
	if idx != 0 || url != c.endpoints[0].url {
		t.Fatalf("expected idx=0, got %d url=%q", idx, url)
	}
	if eligible != 1 {
		t.Fatalf("expected eligible=1 (only one not-blacklisted endpoint), got %d", eligible)
	}
}

// TestClassifyRelayFailure_Forbidden verifies HTTP 403 is classified as
// session-permanent, regardless of body content.
func TestClassifyRelayFailure_Forbidden(t *testing.T) {
	class := classifyRelayFailure(403, []byte("anything"))
	if class != failClassForbidden {
		t.Fatalf("expected failClassForbidden, got %d", class)
	}
}

// TestClassifyRelayFailure_Quota verifies body-based quota detection works
// across locales (the "urlfetch" keyword is never localized by Apps Script).
func TestClassifyRelayFailure_Quota(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"english", "Service invoked too many times for one day: urlfetch."},
		{"persian", "Exception: سرویس در طول یک روز به دفعات زیاد فراخوان شده است:urlfetch. (خط 16)"},
		{"just_keyword", "urlfetch quota limit reached"},
		{"daily_quota", "You have exceeded your daily quota for this service"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class := classifyRelayFailure(200, []byte(tc.body))
			if class != failClassQuotaExhausted {
				t.Fatalf("expected failClassQuotaExhausted for body %q, got %d", tc.body, class)
			}
		})
	}
}

// TestClassifyRelayFailure_Transient verifies generic HTML error pages fall
// through to normal backoff.
func TestClassifyRelayFailure_Transient(t *testing.T) {
	class := classifyRelayFailure(200, []byte("<html><body>generic error</body></html>"))
	if class != failClassTransient {
		t.Fatalf("expected failClassTransient, got %d", class)
	}
}

// TestCarrier_QuotaEndpointSkipped verifies that a quota-exhausted endpoint
// is excluded from pickRelayEndpoint and shows in the stats line.
func TestCarrier_QuotaEndpointSkipped(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"https://example.invalid/a", "https://example.invalid/b"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	// Mark endpoint 0 as quota-exhausted.
	c.endpointMu.Lock()
	c.endpoints[0].quotaBlacklistedTill = time.Now().Add(1 * time.Hour)
	c.endpointMu.Unlock()

	// Pick should always return endpoint 1.
	for i := 0; i < 10; i++ {
		idx, _, eligible := c.pickRelayEndpointWithEligibility()
		if idx != 1 {
			t.Fatalf("iteration %d: expected idx=1 (skip quota endpoint), got %d", i, idx)
		}
		if eligible != 1 {
			t.Fatalf("iteration %d: expected eligible=1, got %d", i, eligible)
		}
	}

	// Stats line should show QUOTA_HOLD.
	line := c.endpointStatsLine()
	if !strings.Contains(line, "QUOTA_HOLD=") {
		t.Fatalf("stats line should contain QUOTA_HOLD=, got: %s", line)
	}
}

// TestCarrier_DisabledEndpointSkipped verifies that a 403-disabled endpoint
// is permanently excluded from selection and shows DISABLED in stats.
func TestCarrier_DisabledEndpointSkipped(t *testing.T) {
	c, err := New(Config{
		ScriptURLs: []string{"https://example.invalid/a", "https://example.invalid/b"},
		AESKeyHex:  testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	// Disable endpoint 0.
	c.endpointMu.Lock()
	c.endpoints[0].disabledReason = "HTTP 403 Forbidden"
	c.endpointMu.Unlock()

	for i := 0; i < 10; i++ {
		idx, _, _ := c.pickRelayEndpointWithEligibility()
		if idx != 1 {
			t.Fatalf("iteration %d: expected idx=1 (skip disabled), got %d", i, idx)
		}
	}

	line := c.endpointStatsLine()
	if !strings.Contains(line, "DISABLED(") {
		t.Fatalf("stats line should contain DISABLED(, got: %s", line)
	}
}
