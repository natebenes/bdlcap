package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/natebenes/bdlcap/internal/bdc"
	"github.com/natebenes/bdlcap/internal/pcapng"
	"github.com/natebenes/bdlcap/internal/pki"
	"github.com/natebenes/bdlcap/internal/wire"
)

func received(f wire.Function, deviceTS uint64, at time.Time) bdc.Received {
	return bdc.Received{Msg: &wire.Message{Function: f, Timestamp: deviceTS}, At: at}
}

// TestAnchorPreservesIntervals verifies timestamp spacing when the endpoint's
// epoch is unknown (YY.2.2).
func TestAnchorPreservesIntervals(t *testing.T) {
	arrival := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	var a anchor

	first := a.stamp(received(wire.FnFrame, 5_000_000, arrival))
	if !first.Equal(arrival) {
		t.Errorf("first packet stamped %v, want the arrival time %v", first, arrival)
	}
	// The endpoint timestamp advances by 1.5 seconds.
	second := a.stamp(received(wire.FnFrame, 6_500_000, arrival.Add(9*time.Second)))
	if got, want := second.Sub(first), 1500*time.Millisecond; got != want {
		t.Errorf("interval = %v, want %v", got, want)
	}
}

// TestAnchorStampsUntimedMessagesOnArrival verifies Drop and Acknowledge times.
func TestAnchorStampsUntimedMessagesOnArrival(t *testing.T) {
	arrival := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	var a anchor
	a.stamp(received(wire.FnFrame, 1_000_000, arrival))

	at := arrival.Add(3 * time.Second)
	for _, f := range []wire.Function{wire.FnDrop, wire.FnAcknowledge} {
		if got := a.stamp(received(f, 0, at)); !got.Equal(at) {
			t.Errorf("%v stamped %v, want the arrival time %v", f, got, at)
		}
	}
}

func TestAnchorNeverGoesBackwards(t *testing.T) {
	arrival := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	var a anchor
	base := a.stamp(received(wire.FnFrame, 5_000_000, arrival))
	// A decreasing endpoint timestamp must not reorder the capture.
	if got := a.stamp(received(wire.FnFrame, 1_000_000, arrival.Add(time.Second))); got.Before(base) {
		t.Errorf("stamped %v, before the anchor %v", got, base)
	}
}

// TestAnchorResetOnReconnect verifies that a new connection uses a new epoch.
func TestAnchorResetOnReconnect(t *testing.T) {
	var a anchor
	start := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	a.stamp(received(wire.FnFrame, 900_000_000, start))

	a.reset()
	rejoin := start.Add(time.Minute)
	if got := a.stamp(received(wire.FnFrame, 12, rejoin)); !got.Equal(rejoin) {
		t.Errorf("after reset stamped %v, want the arrival time %v", got, rejoin)
	}
}

// TestOriginalLength verifies pcapng lengths for truncated frames.
func TestOriginalLength(t *testing.T) {
	cases := []struct {
		name string
		r    bdc.Received
		want int
	}{
		{
			name: "whole frame",
			r: bdc.Received{
				Raw: make([]byte, 30),
				Msg: &wire.Message{Function: wire.FnFrame, OriginalLength: 12, FrameData: make([]byte, 12)},
			},
			want: 30,
		},
		{
			name: "frame the endpoint truncated",
			r: bdc.Received{
				Raw: make([]byte, 30),
				Msg: &wire.Message{Function: wire.FnFrame, OriginalLength: 1500, FrameData: make([]byte, 12)},
			},
			want: 30 + 1500 - 12,
		},
		{
			name: "message that is not a frame",
			r: bdc.Received{
				Raw: make([]byte, 5),
				Msg: &wire.Message{Function: wire.FnDrop, OriginalLength: 999},
			},
			want: 5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := originalLength(tc.r); got != tc.want {
				t.Errorf("originalLength = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParsePosition(t *testing.T) {
	cases := map[string]wire.Position{
		"":         wire.PositionBoth,
		"both":     wire.PositionBoth,
		"receive":  wire.PositionReceive,
		"transmit": wire.PositionTransmit,
		"RECEIVE":  wire.PositionReceive,
	}
	for in, want := range cases {
		got, err := parsePosition(in)
		if err != nil {
			t.Errorf("parsePosition(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parsePosition(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := parsePosition("sideways"); err == nil {
		t.Error("parsePosition accepted an unknown position")
	}
}

func TestParseMonitorMask(t *testing.T) {
	cases := map[string]byte{
		"":                             0,
		"accepted":                     wire.MonitorAccepted,
		"rejected":                     wire.MonitorRejected,
		"disconnect":                   wire.MonitorDisconnect,
		"accepted,rejected,disconnect": wire.MonitorAll,
		" accepted , disconnect ":      wire.MonitorAccepted | wire.MonitorDisconnect,
	}
	for in, want := range cases {
		got, err := parseMonitorMask(in)
		if err != nil {
			t.Errorf("parseMonitorMask(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseMonitorMask(%q) = %#02x, want %#02x", in, got, want)
		}
	}
	if _, err := parseMonitorMask("everything"); err == nil {
		t.Error("parseMonitorMask accepted an unknown diagnostic")
	}
}

func TestParseLinkType(t *testing.T) {
	for _, v := range []uint{uint(pcapng.LinkTypeUser0), uint(pcapng.LinkTypeUser15), 155} {
		if _, err := parseLinkType(v); err != nil {
			t.Errorf("parseLinkType(%d): %v", v, err)
		}
	}
	for _, v := range []uint{0, 1, 146, 163, 1000} {
		if _, err := parseLinkType(v); err == nil {
			t.Errorf("parseLinkType(%d) accepted a value outside the private-use range", v)
		}
	}
}

func TestBuildClientConfigRequiresConnectionOptions(t *testing.T) {
	cases := []struct {
		name string
		f    extcapFlags
	}{
		{"no uri", extcapFlags{}},
		{"port above the instance maximum", extcapFlags{uri: "wss://host/", port: 4194304}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildClientConfig(&tc.f); err == nil {
				t.Fatal("buildClientConfig succeeded, want an error")
			}
		})
	}
}

// TestBuildClientConfigRejectsBadOptions checks the error text because several
// of these options would also fail later, for a different reason.
func TestBuildClientConfigRejectsBadOptions(t *testing.T) {
	cases := []struct {
		name    string
		f       extcapFlags
		wantErr string
	}{
		{"credentials in the URI", extcapFlags{uri: "wss://user:secret@host/"}, "must not contain credentials"},
		{"username in the URI", extcapFlags{uri: "wss://user@host/"}, "must not contain credentials"},
		{"colon in the username", extcapFlags{username: "a:b"}, "must not contain a colon"},
		{"control character in the username", extcapFlags{username: "a\nb"}, "must not contain control"},
		{"control character in the password", extcapFlags{username: "a", password: "secret\n"}, "must not contain control"},
		{"password without a username", extcapFlags{password: "secret"}, "requires --username"},
		{"insecure with ca", extcapFlags{insecure: true, ca: "a"}, "cannot be combined"},
		{"insecure with fingerprint", extcapFlags{insecure: true, fingerprint: "00"}, "cannot be combined"},
		{"ca with fingerprint", extcapFlags{ca: "a", fingerprint: "00"}, "cannot be combined"},
		{"short fingerprint", extcapFlags{fingerprint: "00"}, "fingerprint is 1 octets"},
		{"missing ca file", extcapFlags{ca: filepath.Join(t.TempDir(), "absent.pem")}, "reading certificates"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.f.uri == "" {
				tc.f.uri = "wss://host/"
			}
			tc.f.filter = "all"
			_, err := buildClientConfig(&tc.f)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("error %q contains the password", err)
			}
		})
	}
}

// TestBuildClientConfigTrustModes verifies each option selects its mode. The
// modes themselves are tested with real handshakes in internal/pki.
func TestBuildClientConfigTrustModes(t *testing.T) {
	caPath := writeTestCA(t)
	fingerprint := hex.EncodeToString(make([]byte, 32))

	cases := []struct {
		name       string
		f          extcapFlags
		wantRoots  bool
		wantPin    bool
		wantNoAuth bool
		wantServer string
	}{
		{name: "system roots", wantServer: "host"},
		{name: "server name override", f: extcapFlags{sni: "override"}, wantServer: "override"},
		{name: "private roots", f: extcapFlags{ca: caPath}, wantRoots: true, wantServer: "host"},
		{name: "pin", f: extcapFlags{fingerprint: fingerprint}, wantPin: true, wantServer: "host"},
		{name: "insecure", f: extcapFlags{insecure: true}, wantNoAuth: true, wantServer: "host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.f.uri, tc.f.filter = "wss://host:47810/", "all"
			tc.f.username, tc.f.password = "operator", "a:b"
			cfg, err := buildClientConfig(&tc.f)
			if err != nil {
				t.Fatalf("buildClientConfig: %v", err)
			}
			if cfg.Username != "operator" || cfg.Password != "a:b" {
				t.Errorf("credentials = %q, %q", cfg.Username, cfg.Password)
			}
			if got := cfg.TLS.ServerName; got != tc.wantServer {
				t.Errorf("ServerName = %q, want %q", got, tc.wantServer)
			}
			if got := cfg.TLS.RootCAs != nil; got != tc.wantRoots {
				t.Errorf("RootCAs set = %v, want %v", got, tc.wantRoots)
			}
			if got := cfg.TLS.VerifyConnection != nil; got != tc.wantPin {
				t.Errorf("VerifyConnection set = %v, want %v", got, tc.wantPin)
			}
			if got := pki.Unverified(cfg.TLS); got != tc.wantNoAuth {
				t.Errorf("Unverified = %v, want %v", got, tc.wantNoAuth)
			}
			if len(cfg.TLS.Certificates) != 0 {
				t.Error("the configuration offers a client certificate, which YY.5.3 excludes")
			}
		})
	}
}

// writeTestCA writes a self-signed certificate as a PEM file and returns its path.
func writeTestCA(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bdlcap test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	buf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPumpStopsWhenReconnectIsUnauthorized verifies that credentials rejected
// after a successful session end the capture, rather than being retried until
// the device locks the account.
func TestPumpStopsWhenReconnectIsUnauthorized(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="bdc"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{bdc.Subprotocol}})
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		// End the session once the capture is installed, forcing a reconnect.
		_, _, _ = conn.Read(r.Context())
		conn.Close(websocket.StatusNormalClosure, "")
	}))
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	cfg := bdc.Config{
		URI:      "wss" + strings.TrimPrefix(srv.URL, "https"),
		TLS:      &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		Username: "operator",
		Password: "wrong",
		Filter:   wire.MatchAll(),
	}

	w, err := pcapng.NewWriter(io.Discard, pcapng.LinkTypeUser15, "test", ifaceName, "test")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// pump returns nil if this expires, which fails the check below.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	if err := pump(ctx, w, nil, cfg); !errors.Is(err, bdc.ErrUnauthorized) {
		t.Errorf("pump error = %v, want ErrUnauthorized", err)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("endpoint saw %d requests, want 2: one session and one rejected reconnect", got)
	}
}
