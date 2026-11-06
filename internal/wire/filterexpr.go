package wire

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ParseFilter compiles a capture filter expression into a BACnetCaptureFilter.
//
// The grammar is:
//
//	expr      := orExpr
//	orExpr    := andExpr ( "or" andExpr )*
//	andExpr   := unary ( "and" unary )*
//	unary     := "not" unary | "(" expr ")" | predicate
//	predicate := "all"
//	           | "src" mac | "dst" mac
//	           | "dlmsg" uint | "netmsg" uint | "apdu" uint
//	           | "confirmed" uint | "unconfirmed" uint
//	mac       := hex octets, optionally ':' or '-' separated, or '#' followed
//	             by a decimal value for a one-octet address
//
// "and" binds tighter than "or". Both associate to the left. Numbers are
// decimal unless prefixed with 0x. Write an MS/TP station address as "0c" or
// "#12".
//
// Examples:
//
//	all
//	src #12 or dst #12
//	apdu 0 and confirmed 15
//	not (dlmsg 0x0a)
func ParseFilter(expr string) (Filter, error) {
	toks, err := tokenize(expr)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("wire: empty capture filter expression")
	}
	p := &filterParser{toks: toks, src: expr}
	f, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.i < len(p.toks) {
		return nil, p.errorAt(p.i, "unexpected %q", p.toks[p.i].text)
	}
	return f, nil
}

type token struct {
	text string
	pos  int
}

func tokenize(s string) ([]token, error) {
	var toks []token
	for i := 0; i < len(s); {
		r := rune(s[i])
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '(' || r == ')':
			toks = append(toks, token{string(r), i})
			i++
		default:
			start := i
			for i < len(s) && !unicode.IsSpace(rune(s[i])) && s[i] != '(' && s[i] != ')' {
				i++
			}
			toks = append(toks, token{s[start:i], start})
		}
	}
	return toks, nil
}

type filterParser struct {
	toks []token
	src  string
	i    int
}

func (p *filterParser) errorAt(i int, format string, args ...any) error {
	pos := len(p.src)
	if i < len(p.toks) {
		pos = p.toks[i].pos
	}
	return fmt.Errorf("wire: capture filter at offset %d: %s", pos, fmt.Sprintf(format, args...))
}

// peek returns the current token in lower case.
func (p *filterParser) peek() string {
	if p.i >= len(p.toks) {
		return ""
	}
	return strings.ToLower(p.toks[p.i].text)
}

func (p *filterParser) parseOr() (Filter, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.i++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = Or(left, right)
	}
	return left, nil
}

func (p *filterParser) parseAnd() (Filter, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.i++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = And(left, right)
	}
	return left, nil
}

func (p *filterParser) parseUnary() (Filter, error) {
	switch p.peek() {
	case "":
		return nil, p.errorAt(p.i, "expected a filter term")
	case "not":
		p.i++
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return Not(inner), nil
	case "(":
		p.i++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, p.errorAt(p.i, "expected ')'")
		}
		p.i++
		return inner, nil
	case ")":
		return nil, p.errorAt(p.i, "unexpected ')'")
	}
	return p.parsePredicate()
}

// predicateLimits contains the inclusive upper bound for each numeric predicate.
var predicateLimits = map[string]uint32{
	"dlmsg":       0xFFFFFFFF,
	"netmsg":      0xFF,
	"apdu":        7,
	"confirmed":   0xFF,
	"unconfirmed": 0xFF,
}

func (p *filterParser) parsePredicate() (Filter, error) {
	keyword := p.peek()
	at := p.i
	p.i++

	if keyword == "all" {
		return MatchAll(), nil
	}

	if p.i >= len(p.toks) {
		return nil, p.errorAt(p.i, "%q needs a value", keyword)
	}
	arg := p.toks[p.i].text
	argAt := p.i
	p.i++

	switch keyword {
	case "src", "dst":
		mac, err := parseMAC(arg)
		if err != nil {
			return nil, p.errorAt(argAt, "%s", err)
		}
		if keyword == "src" {
			return SrcMAC(mac), nil
		}
		return DstMAC(mac), nil
	}

	limit, ok := predicateLimits[keyword]
	if !ok {
		return nil, p.errorAt(at, "unknown filter term %q", p.toks[at].text)
	}
	v, err := strconv.ParseUint(arg, 0, 32)
	if err != nil {
		return nil, p.errorAt(argAt, "%q is not a number", arg)
	}
	if uint32(v) > limit {
		return nil, p.errorAt(argAt, "%s %d exceeds the maximum of %d", keyword, v, limit)
	}
	switch keyword {
	case "dlmsg":
		return DatalinkMessageType(uint32(v)), nil
	case "netmsg":
		return NetworkMessageType(uint8(v)), nil
	case "apdu":
		return APDUType(uint8(v)), nil
	case "confirmed":
		return ConfirmedService(uint8(v)), nil
	default:
		return UnconfirmedService(uint8(v)), nil
	}
}

// parseMAC accepts a hexadecimal address with optional separators or a
// #-prefixed decimal MS/TP address.
func parseMAC(s string) ([]byte, error) {
	if rest, ok := strings.CutPrefix(s, "#"); ok {
		v, err := strconv.ParseUint(rest, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("%q is not a decimal mac address in 0..255", s)
		}
		return []byte{byte(v)}, nil
	}
	clean := strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if clean == "" || len(clean)%2 != 0 {
		return nil, fmt.Errorf("%q is not a whole number of hex octets", s)
	}
	mac, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%q is not a hex mac address", s)
	}
	return mac, nil
}
