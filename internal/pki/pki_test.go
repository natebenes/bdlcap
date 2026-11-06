package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCA is a self-signed issuer for test certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// issue signs a server certificate for the DNS name, valid over the given window.
func (ca *testCA) issue(t *testing.T, dnsName string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// valid returns a current certificate for the DNS name.
func (ca *testCA) valid(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	return ca.issue(t, dnsName, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func (ca *testCA) writePEM(t *testing.T, path string) string {
	t.Helper()
	buf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// handshake runs a real TLS handshake of client against a server presenting
// cert, and returns the state the server saw and the client's error.
func handshake(t *testing.T, client *tls.Config, cert tls.Certificate) (tls.ConnectionState, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// A socket rather than net.Pipe, whose unbuffered writes would block a client
	// sending its failure alert while the server is still writing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer ln.Close()

	done := make(chan tls.ConnectionState, 1)
	go func() {
		defer close(done)
		sc, err := ln.Accept()
		if err != nil {
			return
		}
		defer sc.Close()
		// RequestClientCert asks for a client certificate without requiring one.
		s := tls.Server(sc, &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequestClientCert,
			MinVersion:   tls.VersionTLS13,
		})
		_ = s.HandshakeContext(ctx)
		// TLS 1.3 completes the server's side with the client's final flight, so
		// the state is only complete once the handshake has returned.
		done <- s.ConnectionState()
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialing: %v", err)
	}
	defer cc.Close()
	err = tls.Client(cc, client).HandshakeContext(ctx)
	if err != nil {
		cc.Close()
	}
	return <-done, err
}

func TestLoadRoots(t *testing.T) {
	dir := t.TempDir()
	one := newTestCA(t, "one")
	two := newTestCA(t, "two")
	onePath := one.writePEM(t, filepath.Join(dir, "one.pem"))
	twoPath := two.writePEM(t, filepath.Join(dir, "two.pem"))

	a, err := os.ReadFile(onePath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(twoPath)
	if err != nil {
		t.Fatal(err)
	}
	// Other block types, such as a private key, are skipped.
	other := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})
	bundle := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(bundle, append(append(a, other...), b...), 0o600); err != nil {
		t.Fatal(err)
	}

	pool, err := LoadRoots(bundle)
	if err != nil {
		t.Fatalf("LoadRoots: %v", err)
	}
	// Both certificates in the bundle must be usable as roots.
	for _, ca := range []*testCA{one, two} {
		cfg := ClientTLSConfig("endpoint.test", Trust{Roots: pool})
		if _, err := handshake(t, cfg, ca.valid(t, "endpoint.test")); err != nil {
			t.Errorf("handshake with a certificate from %s: %v", ca.cert.Subject.CommonName, err)
		}
	}
}

func TestLoadRootsErrors(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(dir, "corrupt.pem")
	buf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	if err := os.WriteFile(corrupt, buf, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, path, want string
	}{
		{"missing file", filepath.Join(dir, "absent.pem"), "reading certificates"},
		{"no certificates", empty, "no certificates"},
		{"corrupt certificate", corrupt, "parsing a certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadRoots(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestParseFingerprint(t *testing.T) {
	const plain = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	colons := "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:" +
		"00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"

	for _, s := range []string{plain, strings.ToUpper(plain), colons} {
		got, err := ParseFingerprint(s)
		if err != nil {
			t.Errorf("ParseFingerprint(%q): %v", s, err)
			continue
		}
		if len(got) != 32 || got[1] != 0x11 || got[31] != 0xFF {
			t.Errorf("ParseFingerprint(%q) = %x", s, got)
		}
	}
	for _, s := range []string{"", "00112233", plain + "00", "zz" + plain[2:]} {
		if _, err := ParseFingerprint(s); err == nil {
			t.Errorf("ParseFingerprint(%q) succeeded, want an error", s)
		}
	}
}

func TestClientTLSConfigVerification(t *testing.T) {
	const host = "endpoint.test"
	now := time.Now()
	trusted := newTestCA(t, "trusted")
	other := newTestCA(t, "other")

	good := trusted.valid(t, host)
	pinned := func(c tls.Certificate) []byte {
		fp, err := ParseFingerprint(Fingerprint(c.Leaf))
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}
	expired := trusted.issue(t, host, now.Add(-2*time.Hour), now.Add(-time.Hour))
	future := trusted.issue(t, host, now.Add(time.Hour), now.Add(2*time.Hour))
	elsewhere := trusted.valid(t, "other.test")
	foreign := other.valid(t, host)

	cases := []struct {
		name    string
		trust   Trust
		cert    tls.Certificate
		wantErr string
	}{
		{"roots accept a matching certificate", Trust{Roots: trusted.pool()}, good, ""},
		{"roots reject another issuer", Trust{Roots: trusted.pool()}, foreign, "unknown authority"},
		{"roots reject the wrong hostname", Trust{Roots: trusted.pool()}, elsewhere, "is valid for other.test"},
		{"roots reject an expired certificate", Trust{Roots: trusted.pool()}, expired, "expired"},
		{"roots reject a future certificate", Trust{Roots: trusted.pool()}, future, "not yet valid"},
		{"system roots reject a private CA", Trust{}, good, "unknown authority"},

		{"pin accepts the pinned certificate", Trust{Fingerprint: pinned(good)}, good, ""},
		{"pin rejects another certificate", Trust{Fingerprint: pinned(good)}, foreign, "does not match the pinned fingerprint"},
		// The pin replaces every other check, which factory certificates need.
		{"pin ignores the hostname", Trust{Fingerprint: pinned(elsewhere)}, elsewhere, ""},
		{"pin ignores validity dates", Trust{Fingerprint: pinned(expired)}, expired, ""},

		{"insecure accepts anything", Trust{Insecure: true}, foreign, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handshake(t, ClientTLSConfig(host, tc.trust), tc.cert)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("handshake: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("handshake succeeded, want %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestPinFailureNamesPresentedCertificate verifies the operator can see which
// certificate the endpoint presented.
func TestPinFailureNamesPresentedCertificate(t *testing.T) {
	ca := newTestCA(t, "ca")
	cert := ca.valid(t, "endpoint.test")
	cfg := ClientTLSConfig("endpoint.test", Trust{Fingerprint: make([]byte, 32)})
	_, err := handshake(t, cfg, cert)
	if err == nil || !strings.Contains(err.Error(), Fingerprint(cert.Leaf)) {
		t.Errorf("error = %v, want it to contain %s", err, Fingerprint(cert.Leaf))
	}
}

// TestNoClientCertificate verifies YY.5.3: even when an endpoint asks, the tool
// offers no certificate in any trust mode.
func TestNoClientCertificate(t *testing.T) {
	ca := newTestCA(t, "ca")
	cert := ca.valid(t, "endpoint.test")
	fp, err := ParseFingerprint(Fingerprint(cert.Leaf))
	if err != nil {
		t.Fatal(err)
	}
	for name, trust := range map[string]Trust{
		"roots":    {Roots: ca.pool()},
		"pin":      {Fingerprint: fp},
		"insecure": {Insecure: true},
	} {
		t.Run(name, func(t *testing.T) {
			state, err := handshake(t, ClientTLSConfig("endpoint.test", trust), cert)
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if !state.HandshakeComplete {
				t.Fatal("server did not complete the handshake")
			}
			if len(state.PeerCertificates) != 0 {
				t.Errorf("tool presented %d client certificates, want none", len(state.PeerCertificates))
			}
		})
	}
}

func TestClientTLSConfigRequiresTLS13(t *testing.T) {
	for name, trust := range map[string]Trust{
		"default":  {},
		"pin":      {Fingerprint: make([]byte, 32)},
		"insecure": {Insecure: true},
	} {
		// YY.5 requires TLS 1.3 support.
		if cfg := ClientTLSConfig("endpoint.test", trust); cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("%s: MinVersion = %#x, want TLS 1.3", name, cfg.MinVersion)
		}
	}
}

// TestFetchCertificate verifies that a certificate can be viewed even when it
// would fail every check, since seeing why is the point.
func TestFetchCertificate(t *testing.T) {
	ca := newTestCA(t, "untrusted")
	now := time.Now()
	expired := ca.issue(t, "other.test", now.Add(-2*time.Hour), now.Add(-time.Hour))

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{expired},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()

	got, err := FetchCertificate(t.Context(), ln.Addr().String(), "endpoint.test")
	if err != nil {
		t.Fatalf("FetchCertificate: %v", err)
	}
	if Fingerprint(got) != Fingerprint(expired.Leaf) {
		t.Errorf("fetched %s, want %s", Fingerprint(got), Fingerprint(expired.Leaf))
	}
}

func TestFetchCertificateUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	address := ln.Addr().String()
	ln.Close()

	if _, err := FetchCertificate(t.Context(), address, "endpoint.test"); err == nil {
		t.Fatal("FetchCertificate succeeded, want an error")
	}
}

func TestUnverified(t *testing.T) {
	cases := []struct {
		trust Trust
		want  bool
	}{
		{Trust{}, false},
		{Trust{Roots: x509.NewCertPool()}, false},
		{Trust{Fingerprint: make([]byte, 32)}, false},
		{Trust{Insecure: true}, true},
	}
	for _, tc := range cases {
		if got := Unverified(ClientTLSConfig("h", tc.trust)); got != tc.want {
			t.Errorf("Unverified(%+v) = %v, want %v", tc.trust, got, tc.want)
		}
	}
}

func TestDescribeError(t *testing.T) {
	ca := newTestCA(t, "ca")
	cert := ca.valid(t, "endpoint.test")
	_, err := handshake(t, ClientTLSConfig("endpoint.test", Trust{}), cert)
	if err == nil {
		t.Fatal("handshake succeeded, want a verification failure")
	}

	got := DescribeError(fmt.Errorf("dialing: %w", err))
	if !strings.Contains(got.Error(), Fingerprint(cert.Leaf)) {
		t.Errorf("DescribeError = %q, want the fingerprint %s", got, Fingerprint(cert.Leaf))
	}
	if _, ok := errors.AsType[*tls.CertificateVerificationError](got); !ok {
		t.Error("DescribeError lost the original error")
	}

	plain := errors.New("connection refused")
	if got := DescribeError(plain).Error(); got != plain.Error() {
		t.Errorf("DescribeError changed an unrelated error to %q", got)
	}
}
