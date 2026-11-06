package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/natebenes/bdlcap/internal/pcapng"
	"github.com/natebenes/bdlcap/internal/wire"
)

// ifaceName is the extcap interface exposed by bdlcap. The endpoint URI is a
// separate option because devices publish it in the Diagnostic_Endpoint_URIs
// property (Clause 12.11.X), which bdlcap cannot read without a BACnet stack.
const ifaceName = "bdc"

const ifaceDisplay = "BACnet Diagnostic Connection"

// extcapFlags contains the extcap and capture command-line options.
type extcapFlags struct {
	interfaces bool
	dlts       bool
	config     bool
	capture    bool

	extcapVersion string
	iface         string
	fifo          string
	captureFilter string
	controlIn     string
	controlOut    string
	reloadOption  string

	uri         string
	username    string
	password    string
	ca          string
	fingerprint string
	sni         string
	insecure    bool
	port        uint
	position    string
	filter      string
	monitor     string
	linkType    uint
	debug       bool
}

func extcap(args []string) error {
	var f extcapFlags
	fs := flag.NewFlagSet("bdlcap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.BoolVar(&f.interfaces, "extcap-interfaces", false, "list the interfaces this extcap provides")
	fs.BoolVar(&f.dlts, "extcap-dlts", false, "list the link types of an interface")
	fs.BoolVar(&f.config, "extcap-config", false, "list the configuration options of an interface")
	fs.BoolVar(&f.capture, "capture", false, "start capturing")
	fs.StringVar(&f.extcapVersion, "extcap-version", "", "the calling Wireshark version")
	fs.StringVar(&f.iface, "extcap-interface", "", "the interface to operate on")
	fs.StringVar(&f.fifo, "fifo", "", "the fifo to write the capture to")
	fs.StringVar(&f.captureFilter, "extcap-capture-filter", "", "capture filter expression from the interface list")
	fs.StringVar(&f.controlIn, "extcap-control-in", "", "control channel from Wireshark")
	fs.StringVar(&f.controlOut, "extcap-control-out", "", "control channel to Wireshark")
	fs.StringVar(&f.reloadOption, "extcap-reload-option", "", "reload the values of one option")

	fs.StringVar(&f.uri, "uri", "", "diagnostic endpoint URI (wss://host:port/path)")
	fs.StringVar(&f.username, "username", "", "HTTP Basic username (default: send no credentials)")
	fs.StringVar(&f.password, "password", "", "HTTP Basic password; visible to other local users in the process list")
	fs.StringVar(&f.ca, "ca", "", "PEM file of certificates to trust instead of the system roots")
	fs.StringVar(&f.fingerprint, "fingerprint", "", "SHA-256 fingerprint of the endpoint's certificate to pin")
	fs.StringVar(&f.sni, "sni", "", "TLS server name to send and verify (default: the URI hostname)")
	fs.BoolVar(&f.insecure, "insecure", false, "do not verify the endpoint's certificate; credentials may reach an impostor")
	fs.UintVar(&f.port, "port", uint(wire.AllNetworkPorts), "network port instance to capture from")
	fs.StringVar(&f.position, "position", "both", "capture position: receive, transmit, or both")
	fs.StringVar(&f.filter, "filter", "all", "capture filter expression")
	fs.StringVar(&f.monitor, "monitor", "", "diagnostics to monitor: accepted, rejected, disconnect")
	fs.UintVar(&f.linkType, "linktype", uint(pcapng.LinkTypeUser15), "pcapng link type to write")
	fs.BoolVar(&f.debug, "debug", false, "log to stderr")

	if err := fs.Parse(args); err != nil {
		return err
	}

	switch {
	case f.interfaces:
		printInterfaces()
		return nil
	case f.dlts:
		if err := requireInterface(f.iface); err != nil {
			return err
		}
		printDLTs()
		return nil
	case f.config:
		if err := requireInterface(f.iface); err != nil {
			return err
		}
		printConfig()
		return nil
	case f.capture:
		if err := requireInterface(f.iface); err != nil {
			return err
		}
		if f.fifo == "" {
			return fmt.Errorf("--capture requires --fifo")
		}
		return capture(&f)
	case f.reloadOption != "":
		// No option supports reloading.
		return nil
	}
	usage()
	os.Exit(2)
	return nil
}

func requireInterface(name string) error {
	if name != ifaceName {
		return fmt.Errorf("unknown interface %q, want %q", name, ifaceName)
	}
	return nil
}

func printInterfaces() {
	fmt.Printf("extcap {version=%s}{help=%s}{display=%s}\n", version, helpURL, ifaceDisplay)
	fmt.Printf("interface {value=%s}{display=%s}\n", ifaceName, ifaceDisplay)
	// This channel reports status, drops, and NAKs. It accepts no toolbar input.
	fmt.Printf("control {number=0}{type=string}{display=Status}{tooltip=Diagnostic connection status}\n")
}

func printDLTs() {
	// Wireshark requests this value before reading the configured link type.
	// The capture stream identifies any non-default selection.
	fmt.Printf("dlt {number=%d}{name=USER15}{display=BACnet Diagnostic Connection Control}\n",
		pcapng.LinkTypeUser15)
}

func printConfig() {
	fmt.Printf("arg {number=0}{call=--uri}{display=Endpoint URI}" +
		"{tooltip=One of the device's Diagnostic_Endpoint_URIs, for example wss://device.example.com:47810/}" +
		"{type=string}{required=true}{placeholder=wss://host:port/}{group=Endpoint}\n")

	fmt.Printf("arg {number=1}{call=--username}{display=Username}" +
		"{tooltip=HTTP Basic username; leave empty to send no credentials}" +
		"{type=string}{group=Authentication}\n")
	fmt.Printf("arg {number=2}{call=--password}{display=Password}" +
		"{tooltip=HTTP Basic password; visible to other local users in the process list during a capture}" +
		"{type=password}{group=Authentication}\n")

	fmt.Printf("arg {number=3}{call=--ca}{display=Trusted certificates}" +
		"{tooltip=PEM file of certificates to trust instead of the system roots; " +
		"the endpoint's hostname is still verified}" +
		"{type=fileselect}{mustexist=true}{group=TLS}\n")
	fmt.Printf("arg {number=4}{call=--fingerprint}{display=Pinned certificate fingerprint}" +
		"{tooltip=SHA-256 fingerprint of the endpoint's certificate, for example a self-signed one; " +
		"replaces all other certificate checks. Run bdlcap fingerprint wss://host:port/ to view it}" +
		"{type=string}{group=TLS}\n")
	fmt.Printf("arg {number=5}{call=--sni}{display=TLS server name}" +
		"{tooltip=Server name to send in the TLS handshake and verify; defaults to the URI hostname}" +
		"{type=string}{group=TLS}\n")
	fmt.Printf("arg {number=6}{call=--insecure}{display=Do not verify the certificate}" +
		"{tooltip=Accept any certificate; an impostor could receive the credentials}" +
		"{type=boolflag}{group=TLS}\n")

	fmt.Printf("arg {number=7}{call=--port}{display=Network port instance}"+
		"{tooltip=Instance number of the Network Port object to capture from; %d captures every port}"+
		"{type=unsigned}{default=%d}{group=Capture}\n", wire.AllNetworkPorts, wire.AllNetworkPorts)

	fmt.Printf("arg {number=8}{call=--position}{display=Capture position}" +
		"{tooltip=Which side of the network port to install the filter on}" +
		"{type=selector}{default=both}{group=Capture}\n")
	fmt.Printf("value {arg=8}{value=both}{display=Both}{default=true}\n")
	fmt.Printf("value {arg=8}{value=receive}{display=Receive}\n")
	fmt.Printf("value {arg=8}{value=transmit}{display=Transmit}\n")

	fmt.Printf("arg {number=9}{call=--filter}{display=Capture filter}" +
		"{tooltip=for example: all | src #12 | apdu 0 and confirmed 15 | not (dlmsg 10)}" +
		"{type=string}{default=all}{group=Capture}\n")

	fmt.Printf("arg {number=10}{call=--monitor}{display=Diagnostics}" +
		"{tooltip=Connection events to report, for connection-oriented data links such as BACnet/SC}" +
		"{type=multicheck}{group=Capture}\n")
	fmt.Printf("value {arg=10}{value=accepted}{display=Accepted connections}{enabled=true}\n")
	fmt.Printf("value {arg=10}{value=rejected}{display=Rejected connections}{enabled=true}\n")
	fmt.Printf("value {arg=10}{value=disconnect}{display=Disconnections}{enabled=true}\n")

	fmt.Printf("arg {number=11}{call=--linktype}{display=Link type}"+
		"{tooltip=Private-use pcapng link type to write; must match ENCAP in wireshark/bdc.lua}"+
		"{type=selector}{default=%d}{group=Capture}\n", pcapng.LinkTypeUser15)
	for lt := pcapng.LinkTypeUser0; lt <= pcapng.LinkTypeUser15; lt++ {
		def := ""
		if lt == pcapng.LinkTypeUser15 {
			def = "{default=true}"
		}
		fmt.Printf("value {arg=11}{value=%d}{display=USER%d (%d)}%s\n", lt, lt-pcapng.LinkTypeUser0, lt, def)
	}
}

// parsePosition maps the selector value to a capture position (Table YY-3).
func parsePosition(s string) (wire.Position, error) {
	switch strings.ToLower(s) {
	case "", "both":
		return wire.PositionBoth, nil
	case "receive", "rx":
		return wire.PositionReceive, nil
	case "transmit", "tx":
		return wire.PositionTransmit, nil
	}
	return 0, fmt.Errorf("unknown capture position %q, want receive, transmit, or both", s)
}

// parseMonitorMask maps the multicheck selection to a diagnostic mask
// (YY.2.4.1).
func parseMonitorMask(s string) (byte, error) {
	var mask byte
	for _, name := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "":
		case "accepted":
			mask |= wire.MonitorAccepted
		case "rejected":
			mask |= wire.MonitorRejected
		case "disconnect", "disconnection":
			mask |= wire.MonitorDisconnect
		default:
			return 0, fmt.Errorf("unknown diagnostic %q, want accepted, rejected, or disconnect", name)
		}
	}
	return mask, nil
}

// parseLinkType validates a private-use pcap link type.
func parseLinkType(v uint) (uint16, error) {
	if v < uint(pcapng.LinkTypeUser0) || v > uint(pcapng.LinkTypeUser15) {
		return 0, fmt.Errorf("link type %s is outside the private-use range %d..%d",
			strconv.FormatUint(uint64(v), 10), pcapng.LinkTypeUser0, pcapng.LinkTypeUser15)
	}
	return uint16(v), nil
}
