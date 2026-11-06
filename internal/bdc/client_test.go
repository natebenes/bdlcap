package bdc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/natebenes/bdlcap/internal/wire"
)

type readResult struct {
	binary bool
	data   []byte
	err    error
}

// fakeTransport provides Client I/O without a network.
type fakeTransport struct {
	reads chan readResult

	mu        sync.Mutex
	writes    [][]byte
	pings     int
	pingErr   error
	closed    bool
	closeCode CloseCode
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{reads: make(chan readResult, 8)}
}

func (f *fakeTransport) Read(ctx context.Context) (bool, []byte, error) {
	select {
	case <-ctx.Done():
		return false, nil, ctx.Err()
	case r := <-f.reads:
		return r.binary, r.data, r.err
	}
}

func (f *fakeTransport) Write(_ context.Context, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, append([]byte(nil), data...))
	return nil
}

func (f *fakeTransport) Ping(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pings++
	return f.pingErr
}

func (f *fakeTransport) Close(code CloseCode, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed, f.closeCode = true, code
	}
	return nil
}

func (f *fakeTransport) sent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.writes...)
}

func (f *fakeTransport) closeState() (bool, CloseCode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed, f.closeCode
}

func (f *fakeTransport) pingCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pings
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testConfig() Config {
	return Config{
		NetworkPort: wire.AllNetworkPorts,
		Position:    wire.PositionBoth,
		Filter:      wire.MatchAll(),
		Logger:      quietLogger(),
	}
}

func startClient(t *testing.T, tr Transport, cfg Config) *Client {
	t.Helper()
	c, err := Start(context.Background(), tr, cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// TestInstallSendsOneCapture verifies that installation sends one capture
// filter because additional filters can duplicate frames (YY.3).
func TestInstallSendsOneCapture(t *testing.T) {
	tr := newFakeTransport()
	startClient(t, tr, testConfig())

	sent := tr.sent()
	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want just the Capture", len(sent))
	}
	m, err := wire.Decode(sent[0])
	if err != nil {
		t.Fatalf("decoding the Capture: %v", err)
	}
	if m.Function != wire.FnCapture {
		t.Errorf("Function = %v, want Capture", m.Function)
	}
	if m.NetworkPort != wire.AllNetworkPorts {
		t.Errorf("NetworkPort = %d, want the all-ports wildcard", m.NetworkPort)
	}
	if m.Position != wire.PositionBoth {
		t.Errorf("Position = %v, want both", m.Position)
	}
}

func TestInstallSendsMonitorOnlyWhenSelected(t *testing.T) {
	cfg := testConfig()
	cfg.MonitorMask = wire.MonitorAll
	tr := newFakeTransport()
	startClient(t, tr, cfg)

	sent := tr.sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d messages, want a Capture and a Monitor", len(sent))
	}
	m, err := wire.Decode(sent[1])
	if err != nil {
		t.Fatalf("decoding the Monitor: %v", err)
	}
	if m.Function != wire.FnMonitor {
		t.Errorf("Function = %v, want Monitor", m.Function)
	}
	if m.Mask != wire.MonitorAll {
		t.Errorf("Mask = %#02x, want %#02x", m.Mask, wire.MonitorAll)
	}
}

func TestInstallRequiresAFilter(t *testing.T) {
	cfg := testConfig()
	cfg.Filter = nil
	if _, err := Start(context.Background(), newFakeTransport(), cfg); err == nil {
		t.Fatal("Start succeeded without a capture filter")
	}
}

func TestRecvFrame(t *testing.T) {
	tr := newFakeTransport()
	c := startClient(t, tr, testConfig())

	raw := mustHex(t, "11 0000000012345678 000003 0B 10 00000005 06 010203040506 06 0A0B0C0D0E0F 0102030405")
	tr.reads <- readResult{binary: true, data: raw}

	got, err := c.Recv(context.Background())
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if got.Msg.Function != wire.FnFrame {
		t.Errorf("Function = %v, want Frame", got.Msg.Function)
	}
	if got.Msg.NetworkType != wire.NetworkSecureConnect {
		t.Errorf("NetworkType = %v, want secure-connect", got.Msg.NetworkType)
	}
	// Preserve the received bytes for the capture file.
	if string(got.Raw) != string(raw) {
		t.Errorf("Raw = %x, want %x", got.Raw, raw)
	}
	if got.HasAckFor {
		t.Error("HasAckFor is set on a Frame")
	}
}

// TestAcknowledgeCorrelation verifies ordered matching because Acknowledge has
// no request identifier.
func TestAcknowledgeCorrelation(t *testing.T) {
	cfg := testConfig()
	cfg.MonitorMask = wire.MonitorAll
	tr := newFakeTransport()
	c := startClient(t, tr, cfg)

	for range 3 {
		tr.reads <- readResult{binary: true, data: []byte{byte(wire.FnAcknowledge)}}
	}
	want := []struct {
		fn    wire.Function
		known bool
	}{
		{wire.FnCapture, true},
		{wire.FnMonitor, true},
		{0, false}, // an Acknowledge answering nothing outstanding
	}
	for i, w := range want {
		got, err := c.Recv(context.Background())
		if err != nil {
			t.Fatalf("Recv %d: %v", i, err)
		}
		if got.HasAckFor != w.known {
			t.Errorf("acknowledge %d: HasAckFor = %v, want %v", i, got.HasAckFor, w.known)
		}
		if w.known && got.AckFor != w.fn {
			t.Errorf("acknowledge %d: AckFor = %v, want %v", i, got.AckFor, w.fn)
		}
	}
}

func TestRecvProtocolViolations(t *testing.T) {
	cases := []struct {
		name      string
		read      readResult
		wantErr   string
		wantClose CloseCode
	}{
		{
			// BDCC messages use WebSocket binary frames (YY.5.2).
			name:      "non-binary frame",
			read:      readResult{binary: false, data: []byte("hello")},
			wantErr:   "non-binary data frame",
			wantClose: CloseUnsupported,
		},
		{
			// A tool closes after receiving an endpoint-directed message (YY.4).
			name:      "message intended for an endpoint",
			read:      readResult{binary: true, data: []byte{byte(wire.FnMonitor), 0x3F, 0xFF, 0xFF, 0x07}},
			wantErr:   "may not send",
			wantClose: CloseProtocol,
		},
		{
			// Check direction before decoding the truncated payload.
			name:      "truncated message intended for an endpoint",
			read:      readResult{binary: true, data: []byte{byte(wire.FnCapture)}},
			wantErr:   "may not send",
			wantClose: CloseProtocol,
		},
		{
			name:      "empty message",
			read:      readResult{binary: true, data: []byte{}},
			wantErr:   "empty message",
			wantClose: CloseProtocol,
		},
		{
			name:      "undecodable message",
			read:      readResult{binary: true, data: []byte{byte(wire.FnFrame), 0x00}},
			wantErr:   "truncated timestamp",
			wantClose: CloseProtocol,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newFakeTransport()
			c := startClient(t, tr, testConfig())
			tr.reads <- tc.read

			_, err := c.Recv(context.Background())
			if err == nil {
				t.Fatal("Recv succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
			closed, code := tr.closeState()
			if !closed {
				t.Fatal("connection was not closed")
			}
			if code != tc.wantClose {
				t.Errorf("close code = %d, want %d", code, tc.wantClose)
			}
		})
	}
}

func TestRecvPropagatesTransportErrors(t *testing.T) {
	tr := newFakeTransport()
	c := startClient(t, tr, testConfig())
	want := errors.New("connection reset")
	tr.reads <- readResult{err: want}

	if _, err := c.Recv(context.Background()); !errors.Is(err, want) {
		t.Errorf("Recv error = %v, want %v", err, want)
	}
}

// TestMissingPongKeepsConnection verifies that the tool does not rely on the
// endpoint answering pings (YY.5).
func TestMissingPongKeepsConnection(t *testing.T) {
	cfg := testConfig()
	cfg.PingInterval = time.Millisecond
	tr := newFakeTransport()
	tr.pingErr = fmt.Errorf("failed to wait for pong: %w", context.DeadlineExceeded)
	startClient(t, tr, cfg)

	waitForPings(t, tr, 3)
	if closed, _ := tr.closeState(); closed {
		t.Error("the connection closed because an endpoint did not answer a ping")
	}
}

// TestPingFailureClosesConnection verifies a transport failure ends the session,
// which is what starts a reconnect.
func TestPingFailureClosesConnection(t *testing.T) {
	cfg := testConfig()
	cfg.PingInterval = time.Millisecond
	tr := newFakeTransport()
	tr.pingErr = errors.New("connection reset")
	startClient(t, tr, cfg)

	deadline := time.Now().Add(2 * time.Second)
	for {
		if closed, _ := tr.closeState(); closed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the connection stayed open after a transport failure")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForPings(t *testing.T, tr *fakeTransport, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for tr.pingCount() < n {
		if time.Now().After(deadline) {
			t.Fatalf("saw %d pings, want at least %d", tr.pingCount(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPingKeepalive verifies WebSocket keepalive without repeated BDCC requests.
func TestPingKeepalive(t *testing.T) {
	cfg := testConfig()
	cfg.PingInterval = 5 * time.Millisecond
	tr := newFakeTransport()
	c := startClient(t, tr, cfg)

	waitForPings(t, tr, 3)
	if got := len(tr.sent()); got != 1 {
		t.Errorf("sent %d BDCC messages, want only the Capture: pings must not use BDCC", got)
	}
	c.Close()
}

func TestCloseIsIdempotent(t *testing.T) {
	tr := newFakeTransport()
	c := startClient(t, tr, testConfig())
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// dialConfig starts a TLS server running h and returns a Config that reaches it.
func dialConfig(t *testing.T, h http.HandlerFunc) Config {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	cfg := testConfig()
	cfg.URI = "wss" + strings.TrimPrefix(srv.URL, "https")
	cfg.TLS = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	return cfg
}

// basicEndpoint behaves as YY.5.4 requires: a handshake without valid
// credentials gets 401 and a WWW-Authenticate header naming the Basic scheme.
// It reports the first BDCC message of each accepted connection on first.
func basicEndpoint(t *testing.T, username, password string, first chan<- []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="bdc"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer conn.CloseNow()
		_, msg, err := conn.Read(r.Context())
		if err != nil {
			t.Errorf("reading the first message: %v", err)
			return
		}
		first <- msg
		// Read until the client closes, which answers its close frame.
		_, _, _ = conn.Read(r.Context())
	}
}

func TestDialBasicAuthentication(t *testing.T) {
	const username, password = "operator", "a:b:c" // RFC 7617 allows colons in a password.

	cases := []struct {
		name               string
		username, password string
		wantErr            string // empty when the connection should succeed
	}{
		{name: "valid", username: username, password: password},
		{name: "wrong password", username: username, password: "wrong", wantErr: "credentials were rejected"},
		{name: "wrong username", username: "other", password: password, wantErr: "credentials were rejected"},
		{name: "none configured", wantErr: "no username is configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := make(chan []byte, 1)
			cfg := dialConfig(t, basicEndpoint(t, username, password, first))
			cfg.Username, cfg.Password = tc.username, tc.password

			c, err := Dial(t.Context(), cfg)
			if tc.wantErr != "" {
				if !errors.Is(err, ErrUnauthorized) || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Dial error = %v, want ErrUnauthorized and %q", err, tc.wantErr)
				}
				if tc.password != "" && strings.Contains(err.Error(), tc.password) {
					t.Errorf("error %q contains the password", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Close()

			// The connection goes on to install its capture.
			m, err := wire.Decode(<-first)
			if err != nil {
				t.Fatalf("decoding the first message: %v", err)
			}
			if m.Function != wire.FnCapture {
				t.Errorf("first message is %v, want Capture", m.Function)
			}
		})
	}
}

// TestDialSendsNoAuthorizationWithoutUsername covers an endpoint where requiring
// authentication has been turned off.
func TestDialSendsNoAuthorizationWithoutUsername(t *testing.T) {
	seen := make(chan string, 1)
	cfg := dialConfig(t, func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(r.Context())
	})

	c, err := Dial(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if got := <-seen; got != "" {
		t.Errorf("Authorization = %q, want no header", got)
	}
}

// TestDialStatus verifies that only a 401 is reported as ErrUnauthorized, so a
// passing outage is still retried.
func TestDialStatus(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cfg := dialConfig(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			})
			_, err := Dial(t.Context(), cfg)
			if err == nil {
				t.Fatal("Dial succeeded, want an error")
			}
			if errors.Is(err, ErrUnauthorized) {
				t.Errorf("error %v is ErrUnauthorized", err)
			}
		})
	}
}

// TestDialRefusesRedirect verifies credentials cannot follow a redirect.
func TestDialRefusesRedirect(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Store(true)
	}))
	defer target.Close()

	cfg := dialConfig(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	})
	cfg.Username, cfg.Password = "operator", "s3cret"

	_, err := Dial(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("Dial error = %v, want a refused redirect", err)
	}
	if reached.Load() {
		t.Error("the redirect target received a request")
	}
}
