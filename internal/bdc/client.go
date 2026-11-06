// Package bdc implements the diagnostic-tool side of a BACnet Diagnostic
// Connection. It connects over WSS, installs capture settings, and receives
// endpoint messages.
//
// The connection is initially inert; no data flows until a capture filter or
// monitor mask is installed (YY.3).
package bdc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/natebenes/bdlcap/internal/wire"
)

// Subprotocol is the WebSocket subprotocol name of a BACnet Diagnostic
// Connection (YY.5).
const Subprotocol = "bdc.bacnet.org"

// Connection defaults. A ping is sent in case it keeps a quiet connection open,
// but an endpoint may still close one after 600 seconds without BDCC messages
// (YY.3), and no BDCC message can safely be repeated to prevent that: another
// Capture would install a duplicate filter. The capture recovers by reconnecting.
const (
	DefaultPingInterval = 300 * time.Second
	DefaultPingTimeout  = 30 * time.Second
	DefaultReadLimit    = 1 << 20
)

// CloseCode is an RFC 6455 close status code.
type CloseCode int

const (
	CloseNormal      CloseCode = 1000
	CloseProtocol    CloseCode = 1002
	CloseUnsupported CloseCode = 1003
)

// ErrUnauthorized reports that the endpoint answered the WebSocket opening
// handshake with HTTP 401 (YY.5.4).
var ErrUnauthorized = errors.New("the endpoint answered 401 Unauthorized")

// Transport provides the WebSocket operations used by Client.
type Transport interface {
	// Read returns the next message and whether it is binary.
	Read(ctx context.Context) (binary bool, data []byte, err error)
	Write(ctx context.Context, data []byte) error
	Ping(ctx context.Context) error
	Close(code CloseCode, reason string) error
}

// Config describes one diagnostic connection.
type Config struct {
	// URI is the endpoint's wss:// URI, as published in the device's
	// Diagnostic_Endpoint_URIs property (Clause 12.11.X).
	URI string
	TLS *tls.Config

	// Username and Password are the HTTP Basic credentials that authenticate
	// the tool (YY.5.4). They are sent on the opening handshake, which YY.5.4
	// permits, because the tool would otherwise only repeat the handshake with
	// them after a 401. An empty Username sends no credentials.
	Username string
	Password string

	// NetworkPort is the instance number of the network port to capture from;
	// wire.AllNetworkPorts selects every port in the device.
	NetworkPort uint32
	Position    wire.Position
	Filter      wire.Filter

	// MonitorMask selects which connection diagnostics the endpoint should
	// emit. A zero mask installs no monitor.
	MonitorMask byte

	ReadLimit    int64
	PingInterval time.Duration
	PingTimeout  time.Duration
	Logger       *slog.Logger
}

func (c *Config) fillDefaults() {
	if c.ReadLimit == 0 {
		c.ReadLimit = DefaultReadLimit
	}
	if c.PingInterval == 0 {
		c.PingInterval = DefaultPingInterval
	}
	if c.PingTimeout == 0 {
		c.PingTimeout = DefaultPingTimeout
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Position == 0 {
		c.Position = wire.PositionBoth
	}
}

// Received contains a decoded endpoint message and its original bytes.
type Received struct {
	Msg *wire.Message
	Raw []byte
	At  time.Time

	// AckFor identifies the oldest request awaiting this Acknowledge.
	// HasAckFor reports whether AckFor is valid.
	AckFor    wire.Function
	HasAckFor bool
}

// Client is a diagnostic tool's end of one BACnet Diagnostic Connection. Recv
// must be called from a single goroutine.
type Client struct {
	tr  Transport
	cfg Config
	log *slog.Logger

	// ctx controls the connection-wide ping loop.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	pending []wire.Function // requests awaiting an Acknowledge, in order

	closeOnce sync.Once
}

// Dial opens a diagnostic connection and installs its capture settings.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	cfg.fillDefaults()
	u, err := url.Parse(cfg.URI)
	if err != nil {
		return nil, fmt.Errorf("bdc: parsing endpoint URI: %w", err)
	}
	// Annex YY requires a TLS-secured WebSocket connection (YY.5.1).
	if u.Scheme != "wss" {
		return nil, fmt.Errorf("bdc: endpoint URI scheme is %q, want wss", u.Scheme)
	}

	var header http.Header
	if cfg.Username != "" {
		header = http.Header{}
		(&http.Request{Header: header}).SetBasicAuth(cfg.Username, cfg.Password)
	}

	conn, resp, err := websocket.Dial(ctx, cfg.URI, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport:     &http.Transport{TLSClientConfig: cfg.TLS},
			CheckRedirect: refuseRedirect,
		},
		HTTPHeader:   header,
		Subprotocols: []string{Subprotocol},
	})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			if cfg.Username == "" {
				return nil, fmt.Errorf("bdc: dialing %s: %w: no username is configured", cfg.URI, ErrUnauthorized)
			}
			return nil, fmt.Errorf("bdc: dialing %s: %w: the credentials were rejected", cfg.URI, ErrUnauthorized)
		}
		return nil, fmt.Errorf("bdc: dialing %s: %w", cfg.URI, err)
	}
	if got := conn.Subprotocol(); got != Subprotocol {
		conn.Close(websocket.StatusProtocolError, "subprotocol not negotiated")
		return nil, fmt.Errorf("bdc: endpoint negotiated subprotocol %q, want %q", got, Subprotocol)
	}
	conn.SetReadLimit(cfg.ReadLimit)
	return Start(ctx, &wsTransport{conn: conn}, cfg)
}

// refuseRedirect stops the handshake at a redirect. The operator chose and
// verified the configured endpoint, and a redirect could carry the credentials
// to a different host or to an unencrypted ws:// URI, which YY.5.1 does not allow.
func refuseRedirect(*http.Request, []*http.Request) error {
	return errors.New("the endpoint sent a redirect, which is not followed")
}

// Start runs the protocol over an established transport.
func Start(ctx context.Context, tr Transport, cfg Config) (*Client, error) {
	cfg.fillDefaults()
	c := &Client{tr: tr, cfg: cfg, log: cfg.Logger}
	c.ctx, c.cancel = context.WithCancel(context.WithoutCancel(ctx))

	if err := c.install(ctx); err != nil {
		c.cancel()
		tr.Close(CloseNormal, "")
		return nil, err
	}
	c.wg.Go(c.pingLoop)
	return c, nil
}

// install sends one Capture request and an optional Monitor request. Sending a
// second Capture request would install another filter and duplicate frames
// (YY.3.1).
func (c *Client) install(ctx context.Context) error {
	if c.cfg.Filter == nil {
		return errors.New("bdc: a capture filter is required")
	}
	reqs := []*wire.Message{{
		Function:    wire.FnCapture,
		NetworkPort: c.cfg.NetworkPort,
		Position:    c.cfg.Position,
		Filter:      c.cfg.Filter,
	}}
	if c.cfg.MonitorMask != 0 {
		reqs = append(reqs, &wire.Message{
			Function:    wire.FnMonitor,
			NetworkPort: c.cfg.NetworkPort,
			Mask:        c.cfg.MonitorMask,
		})
	}
	for _, m := range reqs {
		raw, err := m.Encode()
		if err != nil {
			return fmt.Errorf("bdc: encoding %v: %w", m.Function, err)
		}
		if err := c.tr.Write(ctx, raw); err != nil {
			return fmt.Errorf("bdc: sending %v: %w", m.Function, err)
		}
		c.mu.Lock()
		c.pending = append(c.pending, m.Function)
		c.mu.Unlock()
		c.log.Debug("sent request", "function", m.Function, "port", m.NetworkPort)
	}
	return nil
}

// Recv returns the next message from the endpoint.
func (c *Client) Recv(ctx context.Context) (Received, error) {
	for {
		binary, raw, err := c.tr.Read(ctx)
		if err != nil {
			return Received{}, err
		}
		// BDCC messages must use WebSocket binary frames (YY.5.2).
		if !binary {
			c.tr.Close(CloseUnsupported, "non-binary data frame")
			return Received{}, errors.New("bdc: endpoint sent a non-binary data frame")
		}
		// Close when the endpoint sends a tool-to-endpoint function. Check the
		// function byte before decoding the payload (YY.4).
		if len(raw) == 0 {
			c.tr.Close(CloseProtocol, "empty BDCC message")
			return Received{}, errors.New("bdc: endpoint sent an empty message")
		}
		if fn := wire.Function(raw[0]); !fn.FromEndpoint() {
			c.tr.Close(CloseProtocol, "message intended for a diagnostic endpoint")
			return Received{}, fmt.Errorf("bdc: endpoint sent %v, which a diagnostic endpoint may not send", fn)
		}
		msg, err := wire.Decode(raw)
		if err != nil {
			c.tr.Close(CloseProtocol, "undecodable BDCC message")
			return Received{}, err
		}

		r := Received{Msg: msg, Raw: raw, At: time.Now()}
		if msg.Function == wire.FnAcknowledge {
			r.AckFor, r.HasAckFor = c.popPending()
		}
		return r, nil
	}
}

// popPending matches an Acknowledge to the oldest outstanding request because
// BDCC has no request identifiers.
func (c *Client) popPending() (wire.Function, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return 0, false
	}
	f := c.pending[0]
	c.pending = c.pending[1:]
	return f, true
}

// pingLoop sends best-effort WebSocket pings. A missing Pong does not end the
// connection, because implementations shall not rely on the peer's use of Ping
// and Pong (YY.5). A failure to send the ping does.
func (c *Client) pingLoop() {
	t := time.NewTicker(c.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(c.ctx, c.cfg.PingTimeout)
			err := c.tr.Ping(ctx)
			cancel()
			switch {
			case err == nil || c.ctx.Err() != nil:
			case errors.Is(err, context.DeadlineExceeded):
				c.log.Debug("no Pong before the ping timeout", "err", err)
			default:
				c.log.Warn("keepalive ping failed", "err", err)
				c.tr.Close(CloseNormal, "keepalive failure")
				return
			}
		}
	}
}

// Close shuts the connection down. It is safe to call more than once.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.cancel()
		err = c.tr.Close(CloseNormal, "")
		c.wg.Wait()
	})
	return err
}

// wsTransport adapts a WebSocket connection to Transport.
type wsTransport struct{ conn *websocket.Conn }

func (t *wsTransport) Read(ctx context.Context) (bool, []byte, error) {
	typ, data, err := t.conn.Read(ctx)
	if err != nil {
		return false, nil, err
	}
	return typ == websocket.MessageBinary, data, nil
}

func (t *wsTransport) Write(ctx context.Context, data []byte) error {
	return t.conn.Write(ctx, websocket.MessageBinary, data)
}

func (t *wsTransport) Ping(ctx context.Context) error { return t.conn.Ping(ctx) }

func (t *wsTransport) Close(code CloseCode, reason string) error {
	return t.conn.Close(websocket.StatusCode(code), reason)
}
