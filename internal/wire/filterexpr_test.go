package wire

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseFilter(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want string // canonical rendering
	}{
		{"mstp station decimal", "src #12", "src 0c"},
		{"mstp station hex", "src 0c", "src 0c"},
		{"bacnet ip peer", "dst c0:a8:01:0a:ba:c0", "dst c0:a8:01:0a:ba:c0"},
		{"dash separators", "dst c0-a8-01-0a-ba-c0", "dst c0:a8:01:0a:ba:c0"},
		{"apdu type", "apdu 0", "apdu 0"},
		{"hex literal", "dlmsg 0x0a", "dlmsg 10"},
		{"and binds tighter than or", "apdu 0 and apdu 1 or apdu 2",
			"((apdu 0 and apdu 1) or apdu 2)"},
		{"explicit grouping", "apdu 0 and (apdu 1 or apdu 2)",
			"(apdu 0 and (apdu 1 or apdu 2))"},
		{"and is left associative", "apdu 0 and apdu 1 and apdu 2",
			"((apdu 0 and apdu 1) and apdu 2)"},
		{"negation", "not apdu 0", "not (apdu 0)"},
		{"case insensitive keywords", "NOT ( APDU 0 AND APDU 1 )",
			"not ((apdu 0 and apdu 1))"},
		{"services", "confirmed 15 or unconfirmed 8",
			"(confirmed 15 or unconfirmed 8)"},
		{"network message type", "netmsg 1", "netmsg 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseFilter(tc.expr)
			if err != nil {
				t.Fatalf("ParseFilter(%q): %v", tc.expr, err)
			}
			if got := f.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
			// Verify the parsed filter's wire encoding.
			raw := f.encode(nil)
			back, n, err := decodeFilter(raw, 0)
			if err != nil {
				t.Fatalf("decodeFilter(%x): %v", raw, err)
			}
			if n != len(raw) {
				t.Errorf("decodeFilter consumed %d of %d octets", n, len(raw))
			}
			if got := back.String(); got != tc.want {
				t.Errorf("decoded String() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFilterEncoding verifies the Clause 21 context tags for a filter tree.
func TestFilterEncoding(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want string
	}{
		{"source mac", "src 0c", "09 0c"},
		{"destination mac", "dst c0:a8:01:0a:ba:c0", "1d 06 c0a8010abac0"},
		{"apdu type", "apdu 4", "49 04"},
		{"logical not", "not apdu 4", "7e 4904 7f"},
		{"logical and", "apdu 0 and apdu 1", "8e 0e 4900 0f 1e 4901 1f 8f"},
		{"logical or", "apdu 0 or apdu 1", "9e 0e 4900 0f 1e 4901 1f 9f"},
		{"match all", "all", "7e 8e 0e 4900 0f 1e 7e 4900 7f 1f 8f 7f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseFilter(tc.expr)
			if err != nil {
				t.Fatalf("ParseFilter: %v", err)
			}
			want := strings.ReplaceAll(tc.want, " ", "")
			if got := hex.EncodeToString(f.encode(nil)); got != want {
				t.Errorf("encode = %s, want %s", got, want)
			}
		})
	}
}

// TestMatchAllIsTautology verifies the fallback used because
// BACnetCaptureFilter has no explicit match-all choice.
func TestMatchAllIsTautology(t *testing.T) {
	if got, want := MatchAll().String(), "not ((apdu 0 and not (apdu 0)))"; got != want {
		t.Errorf("MatchAll() = %q, want %q", got, want)
	}
}

func TestParseFilterErrors(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want string
	}{
		{"empty", "", "empty capture filter"},
		{"whitespace only", "   ", "empty capture filter"},
		{"unknown term", "srcc 01", "unknown filter term"},
		{"missing value", "src", "needs a value"},
		{"apdu out of range", "apdu 8", "exceeds the maximum of 7"},
		{"netmsg out of range", "netmsg 256", "exceeds the maximum of 255"},
		{"not a number", "apdu xyzzy", "is not a number"},
		{"odd hex mac", "src 0", "whole number of hex octets"},
		{"bad hex mac", "src zz", "is not a hex mac address"},
		{"decimal mac out of range", "src #256", "decimal mac address"},
		{"unbalanced open", "(apdu 0", "expected ')'"},
		{"unbalanced close", "apdu 0)", "unexpected \")\""},
		{"dangling operator", "apdu 0 and", "expected a filter term"},
		{"trailing junk", "apdu 0 apdu 1", "unexpected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFilter(tc.expr)
			if err == nil {
				t.Fatalf("ParseFilter(%q) succeeded, want an error", tc.expr)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}
