package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/natebenes/bdlcap/internal/bdc"
	"github.com/natebenes/bdlcap/internal/pcapng"
	"github.com/natebenes/bdlcap/internal/pki"
	"github.com/natebenes/bdlcap/internal/wire"
)

// Reconnection backoff limits.
const (
	reconnectMinDelay = 1 * time.Second
	reconnectMaxDelay = 30 * time.Second
)

// anchor converts endpoint timestamps to wall-clock times.
//
// A BDCC timestamp counts microseconds from an unspecified epoch that remains
// fixed for one connection (YY.2.2). The first timestamp is assigned its
// arrival time. Later timestamps preserve the endpoint's measured intervals.
type anchor struct {
	set  bool
	wall time.Time
	dev  uint64
}

// reset clears the timestamp base after a reconnect.
func (a *anchor) reset() { a.set = false }

func (a *anchor) stamp(r bdc.Received) time.Time {
	// Drop and Acknowledge have no timestamp, so use their arrival time.
	if !hasTimestamp(r.Msg.Function) {
		return r.At
	}
	if !a.set {
		a.set, a.wall, a.dev = true, r.At, r.Msg.Timestamp
		return r.At
	}
	if r.Msg.Timestamp < a.dev {
		// Prevent an invalid decreasing timestamp from reordering packets.
		return a.wall
	}
	return a.wall.Add(time.Duration(r.Msg.Timestamp-a.dev) * time.Microsecond)
}

func hasTimestamp(f wire.Function) bool {
	switch f {
	case wire.FnFrame, wire.FnConnect, wire.FnDisconnect:
		return true
	}
	return false
}

// originalLength returns the encoded BDCC length before the endpoint truncated
// the frame data (YY.2.6.1, YY.4.1).
func originalLength(r bdc.Received) int {
	n := len(r.Raw)
	if r.Msg.Function == wire.FnFrame {
		n += int(r.Msg.OriginalLength) - len(r.Msg.FrameData)
	}
	return n
}

func capture(f *extcapFlags) error {
	log := newLogger(f.debug)

	clientCfg, err := buildClientConfig(f)
	if err != nil {
		return err
	}
	clientCfg.Logger = log
	linkType, err := parseLinkType(f.linkType)
	if err != nil {
		return err
	}

	ctrl, err := openControl(f.controlIn, f.controlOut)
	if err != nil {
		return fmt.Errorf("opening the control channel: %w", err)
	}
	defer ctrl.Close()

	// Opening the FIFO for writing waits for Wireshark to open the read side.
	fifo, err := os.OpenFile(f.fifo, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("opening the capture fifo: %w", err)
	}
	defer fifo.Close()

	w, err := pcapng.NewWriter(fifo, linkType, "bdlcap "+version, ifaceName,
		"BACnet Diagnostic Connection to "+f.uri)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return pump(ctx, w, ctrl, clientCfg)
}

// pump reconnects after connection failures until the capture stops.
func pump(ctx context.Context, w *pcapng.Writer, ctrl *control, cfg bdc.Config) error {
	var (
		a     anchor
		delay = reconnectMinDelay
		first = true
	)
	for {
		client, err := bdc.Dial(ctx, cfg)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			err = pki.DescribeError(err)
			// Report initial configuration errors instead of retrying them.
			// Retrying rejected credentials could also lock the account.
			if first || errors.Is(err, bdc.ErrUnauthorized) {
				ctrl.Error("Cannot reach the diagnostic endpoint: " + err.Error())
				return err
			}
			ctrl.Warning("Reconnect failed: " + err.Error())
			if !sleep(ctx, delay) {
				return nil
			}
			delay = min(delay*2, reconnectMaxDelay)
			continue
		}
		first, delay = false, reconnectMinDelay
		ctrl.Statusbar("Connected to " + cfg.URI)
		if pki.Unverified(cfg.TLS) {
			ctrl.Warning("Connected without verifying the endpoint's certificate: " +
				"the endpoint may be an impostor, and any credentials were sent to it.")
		}
		a.reset()

		err = session(ctx, client, w, ctrl, &a)
		client.Close()
		if ctx.Err() != nil {
			return nil
		}
		// A capture NAK cannot be fixed by reconnecting.
		var fatal *fatalError
		if errors.As(err, &fatal) {
			ctrl.Error(fatal.Error())
			return err
		}
		ctrl.Warning("Diagnostic connection lost, reconnecting: " + err.Error())
		ctrl.Statusbar("Reconnecting to " + cfg.URI)
		if !sleep(ctx, delay) {
			return nil
		}
	}
}

// session writes endpoint messages to the capture file until the connection ends.
func session(ctx context.Context, client *bdc.Client, w *pcapng.Writer, ctrl *control, a *anchor) error {
	var drops uint64
	for {
		r, err := client.Recv(ctx)
		if err != nil {
			return err
		}
		if err := w.WritePacket(a.stamp(r), originalLength(r), r.Raw); err != nil {
			return err
		}

		switch r.Msg.Function {
		case wire.FnAcknowledge:
			if r.Msg.Err == nil {
				continue
			}
			if r.HasAckFor && r.AckFor == wire.FnCapture {
				return &fatalError{fmt.Errorf("the endpoint refused the capture filter: %w", r.Msg.Err)}
			}
			what := "a request"
			if r.HasAckFor {
				what = r.AckFor.String()
			}
			ctrl.Warning(fmt.Sprintf("The endpoint refused %s: %v", what, r.Msg.Err))
		case wire.FnDrop:
			// The endpoint dropped frames because the tool fell behind (YY.2.7.1).
			drops += uint64(r.Msg.DropCount)
			ctrl.Warning(fmt.Sprintf("The endpoint dropped %d frames (%d in total)", r.Msg.DropCount, drops))
		}
	}
}

// fatalError marks a failure that reconnecting cannot fix.
type fatalError struct{ error }

func (e *fatalError) Unwrap() error { return e.error }

// sleep returns false if the capture stops before d elapses.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// buildClientConfig validates the command-line options and builds a client configuration.
func buildClientConfig(f *extcapFlags) (bdc.Config, error) {
	var cfg bdc.Config
	if f.uri == "" {
		return cfg, errors.New("--uri is required")
	}
	u, err := url.Parse(f.uri)
	if err != nil {
		return cfg, fmt.Errorf("parsing --uri: %w", err)
	}
	// The URI is written to the capture file and shown in status messages, so
	// it must not carry a password.
	if u.User != nil {
		return cfg, errors.New("--uri must not contain credentials; use --username and --password")
	}
	if err := checkCredentials(f.username, f.password); err != nil {
		return cfg, err
	}
	if uint32(f.port) > wire.AllNetworkPorts {
		return cfg, fmt.Errorf("--port %d exceeds the maximum instance number %d", f.port, wire.AllNetworkPorts)
	}

	position, err := parsePosition(f.position)
	if err != nil {
		return cfg, err
	}
	mask, err := parseMonitorMask(f.monitor)
	if err != nil {
		return cfg, err
	}
	// Prefer the expression from Wireshark's capture-filter field.
	expr := f.filter
	if f.captureFilter != "" {
		expr = f.captureFilter
	}
	filter, err := wire.ParseFilter(expr)
	if err != nil {
		return cfg, err
	}

	trust, err := buildTrust(f)
	if err != nil {
		return cfg, err
	}

	cfg = bdc.Config{
		URI:         f.uri,
		TLS:         pki.ClientTLSConfig(cmp.Or(f.sni, u.Hostname()), trust),
		Username:    f.username,
		Password:    f.password,
		NetworkPort: uint32(f.port),
		Position:    position,
		Filter:      filter,
		MonitorMask: mask,
	}
	return cfg, nil
}

// checkCredentials applies the RFC 7617 limits on HTTP Basic credentials. Its
// errors never repeat the values, since one of them is a password.
func checkCredentials(username, password string) error {
	if password != "" && username == "" {
		return errors.New("--password requires --username")
	}
	// A colon would end the username early, when the endpoint splits the pair.
	if strings.Contains(username, ":") {
		return errors.New("--username must not contain a colon")
	}
	if strings.ContainsFunc(username, unicode.IsControl) {
		return errors.New("--username must not contain control characters")
	}
	if strings.ContainsFunc(password, unicode.IsControl) {
		return errors.New("--password must not contain control characters")
	}
	return nil
}

// buildTrust selects one way to verify the endpoint's certificate (YY.5.3).
func buildTrust(f *extcapFlags) (pki.Trust, error) {
	var trust pki.Trust
	switch {
	case f.insecure && (f.ca != "" || f.fingerprint != ""):
		return trust, errors.New("--insecure cannot be combined with --ca or --fingerprint")
	case f.ca != "" && f.fingerprint != "":
		return trust, errors.New("--ca and --fingerprint cannot be combined")
	case f.insecure:
		trust.Insecure = true
	case f.ca != "":
		roots, err := pki.LoadRoots(f.ca)
		if err != nil {
			return trust, err
		}
		trust.Roots = roots
	case f.fingerprint != "":
		fp, err := pki.ParseFingerprint(f.fingerprint)
		if err != nil {
			return trust, err
		}
		trust.Fingerprint = fp
	}
	return trust, nil
}
