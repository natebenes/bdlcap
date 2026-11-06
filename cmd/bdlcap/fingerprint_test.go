package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/natebenes/bdlcap/internal/pki"
)

// TestPrintFingerprint verifies the output can be pinned, and that viewing a
// certificate stops at the TLS handshake, so no credentials could be sent.
func TestPrintFingerprint(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer srv.Close()

	var out bytes.Buffer
	uri := "wss" + strings.TrimPrefix(srv.URL, "https") + "/path"
	if err := printFingerprint(t.Context(), &out, uri, ""); err != nil {
		t.Fatalf("printFingerprint: %v", err)
	}

	got := out.String()
	want := pki.Fingerprint(srv.Certificate())
	if !strings.Contains(got, "SHA-256:  "+want+"\n") {
		t.Errorf("output does not give the fingerprint %s:\n%s", want, got)
	}
	if !strings.Contains(got, "--fingerprint "+want+"\n") {
		t.Errorf("output does not show how to pin it:\n%s", got)
	}
	if !strings.Contains(got, "NOT been verified") {
		t.Errorf("output does not warn that the certificate is unverified:\n%s", got)
	}
	if !strings.Contains(got, "example.com") {
		t.Errorf("output does not list the certificate's names:\n%s", got)
	}
	if _, err := pki.ParseFingerprint(want); err != nil {
		t.Errorf("--fingerprint does not accept the printed value: %v", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the endpoint received %d HTTP requests, want none", n)
	}
}

func TestEndpointAddress(t *testing.T) {
	cases := []struct {
		uri, address, host string
	}{
		{"wss://device.example.com:47810/", "device.example.com:47810", "device.example.com"},
		{"wss://device.example.com/bdc", "device.example.com:443", "device.example.com"},
		{"wss://192.0.2.1:47810", "192.0.2.1:47810", "192.0.2.1"},
		{"wss://[2001:db8::1]:47810/", "[2001:db8::1]:47810", "2001:db8::1"},
		{"wss://[2001:db8::1]/", "[2001:db8::1]:443", "2001:db8::1"},
	}
	for _, tc := range cases {
		address, host, err := endpointAddress(tc.uri)
		if err != nil {
			t.Errorf("endpointAddress(%q): %v", tc.uri, err)
			continue
		}
		if address != tc.address || host != tc.host {
			t.Errorf("endpointAddress(%q) = %q, %q, want %q, %q", tc.uri, address, host, tc.address, tc.host)
		}
	}
	for _, uri := range []string{"", "device.example.com:47810", "ws://host/", "https://host/", "wss:///path", "wss://%zz/"} {
		if _, _, err := endpointAddress(uri); err == nil {
			t.Errorf("endpointAddress(%q) succeeded, want an error", uri)
		}
	}
}

func TestPrintableRemovesControlCharacters(t *testing.T) {
	if got, want := printable("CN=a\x1b[2J\nb\x7f"), "CN=a?[2J?b?"; got != want {
		t.Errorf("printable = %q, want %q", got, want)
	}
	if got, want := printable("CN=Gerät 1"), "CN=Gerät 1"; got != want {
		t.Errorf("printable = %q, want %q", got, want)
	}
}
