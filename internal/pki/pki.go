// Package pki configures how a diagnostic tool verifies a BACnet Diagnostic
// Endpoint's certificate.
//
// Annex YY requires TLS 1.3, does not use client certificates, and leaves the
// choice of endpoint certificate as a local matter (YY.5, YY.5.3). Endpoints
// may therefore hold a publicly trusted certificate, one from a private CA, or
// a self-signed one, and Trust has a mode for each. Verification matters because
// HTTP Basic credentials are sent to whichever server passes it (YY.5.4).
package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// Trust selects how the endpoint certificate is verified. The zero value
// verifies the certificate chain against the system roots, and the hostname.
type Trust struct {
	// Roots replaces the system roots. The hostname is still verified.
	Roots *x509.CertPool

	// Fingerprint pins the SHA-256 hash of the endpoint's certificate. The pin
	// takes the place of chain, hostname, and validity date checks.
	Fingerprint []byte

	// Insecure disables verification, so anyone able to intercept the connection
	// receives the credentials and can impersonate the endpoint.
	Insecure bool
}

// LoadRoots loads trusted certificates from a PEM file, which may contain
// several certificates. Non-certificate blocks are ignored.
func LoadRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pki: reading certificates: %w", err)
	}
	pool := x509.NewCertPool()
	found := false
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parsing a certificate in %s: %w", path, err)
		}
		pool.AddCert(cert)
		found = true
	}
	if !found {
		return nil, fmt.Errorf("pki: no certificates in %s", path)
	}
	return pool, nil
}

// ParseFingerprint decodes a SHA-256 fingerprint written as hexadecimal, with
// optional colons between the octets as openssl prints them.
func ParseFingerprint(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil {
		return nil, fmt.Errorf("pki: fingerprint is not hexadecimal: %w", err)
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("pki: fingerprint is %d octets, want %d", len(b), sha256.Size)
	}
	return b, nil
}

// Fingerprint returns the SHA-256 hash of cert in the form ParseFingerprint
// accepts.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// ClientTLSConfig returns a TLS 1.3 client configuration that presents no client
// certificate. serverName is sent in the handshake and, unless trust replaces
// the check, must match the endpoint's certificate.
func ClientTLSConfig(serverName string, trust Trust) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    trust.Roots,
	}
	switch {
	case trust.Insecure:
		cfg.InsecureSkipVerify = true
	case trust.Fingerprint != nil:
		// VerifyConnection does the verification that this disables. Unlike
		// VerifyPeerCertificate, it also runs on resumed sessions.
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("pki: endpoint presented no certificate")
			}
			leaf := cs.PeerCertificates[0]
			sum := sha256.Sum256(leaf.Raw)
			if !bytes.Equal(sum[:], trust.Fingerprint) {
				return fmt.Errorf("pki: endpoint certificate does not match the pinned fingerprint: it presented %s",
					Fingerprint(leaf))
			}
			return nil
		}
	}
	return cfg
}

// FetchCertificate completes a TLS handshake with address and returns the
// certificate the endpoint presented. It does not verify the certificate and
// sends nothing beyond the handshake, so the result must be confirmed out of band
// before it is trusted.
func FetchCertificate(ctx context.Context, address, serverName string) (*x509.Certificate, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("pki: connecting to the endpoint: %w", err)
	}
	defer conn.Close()

	tc := tls.Client(conn, ClientTLSConfig(serverName, Trust{Insecure: true}))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("pki: TLS handshake with the endpoint: %w", err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("pki: endpoint presented no certificate")
	}
	return certs[0], nil
}

// Unverified reports whether cfg accepts any endpoint certificate.
func Unverified(cfg *tls.Config) bool {
	return cfg != nil && cfg.InsecureSkipVerify && cfg.VerifyConnection == nil
}

// DescribeError adds the fingerprint of the certificate an endpoint presented
// when err is a failed certificate verification, so that an operator can check
// it out of band and, if it is correct, pin it. Other errors are returned as is.
func DescribeError(err error) error {
	verr, ok := errors.AsType[*tls.CertificateVerificationError](err)
	if !ok || len(verr.UnverifiedCertificates) == 0 {
		return err
	}
	return fmt.Errorf("%w (the endpoint presented a certificate with SHA-256 fingerprint %s)",
		err, Fingerprint(verr.UnverifiedCertificates[0]))
}
