package main

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/natebenes/bdlcap/internal/pki"
)

// fingerprintTimeout limits the connection and TLS handshake.
const fingerprintTimeout = 10 * time.Second

// defaultWSSPort is the port of a wss URI that does not name one (RFC 6455).
const defaultWSSPort = "443"

// cmdFingerprint shows the certificate an endpoint presents, so that an operator
// can confirm its fingerprint and pin it without another tool.
func cmdFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	sni := fs.String("sni", "", "TLS server name to send (default: the URI hostname)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: bdlcap fingerprint [-sni NAME] wss://host:port/")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args) // ExitOnError: Parse exits rather than returning an error.
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), fingerprintTimeout)
	defer cancel()
	return printFingerprint(ctx, os.Stdout, fs.Arg(0), *sni)
}

func printFingerprint(ctx context.Context, w io.Writer, uri, sni string) error {
	address, host, err := endpointAddress(uri)
	if err != nil {
		return err
	}
	cert, err := pki.FetchCertificate(ctx, address, cmp.Or(sni, host))
	if err != nil {
		return err
	}

	fp := pki.Fingerprint(cert)
	fmt.Fprintf(w, "Endpoint: %s\n", address)
	fmt.Fprintf(w, "Subject:  %s\n", printable(cert.Subject.String()))
	fmt.Fprintf(w, "Issuer:   %s\n", printable(cert.Issuer.String()))
	fmt.Fprintf(w, "Names:    %s\n", printable(certificateNames(cert)))
	fmt.Fprintf(w, "Valid:    %s to %s\n",
		cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "SHA-256:  %s\n\n", fp)
	fmt.Fprintf(w, "This certificate has NOT been verified, and anyone able to intercept this\n"+
		"connection could have presented it. Confirm the fingerprint with the device or\n"+
		"its administrator, then set it in Wireshark or pass:\n\n"+
		"  --fingerprint %s\n", fp)
	return nil
}

// endpointAddress returns the host:port to dial for a wss URI, and the hostname.
func endpointAddress(uri string) (address, host string, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", fmt.Errorf("parsing the endpoint URI: %w", err)
	}
	if u.Scheme != "wss" {
		return "", "", fmt.Errorf("endpoint URI scheme is %q, want wss", u.Scheme)
	}
	host = u.Hostname()
	if host == "" {
		return "", "", errors.New("endpoint URI has no host")
	}
	return net.JoinHostPort(host, cmp.Or(u.Port(), defaultWSSPort)), host, nil
}

// certificateNames lists the names a certificate is valid for.
func certificateNames(cert *x509.Certificate) string {
	var names []string
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	for _, u := range cert.URIs {
		names = append(names, u.String())
	}
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

// printable replaces control characters, because certificate fields come from an
// unverified server and could otherwise send escape sequences to the terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}
