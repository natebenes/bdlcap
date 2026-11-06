// Command bdlcap captures BACnet traffic from a device's BACnet Diagnostic
// Endpoint and feeds it to Wireshark as an extcap interface.
//
// Wireshark invokes it with extcap arguments. The sample subcommand can be run
// directly.
//
// Usage:
//
//	bdlcap --extcap-interfaces
//	bdlcap --extcap-dlts --extcap-interface bdc
//	bdlcap --extcap-config --extcap-interface bdc
//	bdlcap --extcap-interface bdc --capture --fifo FIFO [options]
//	bdlcap fingerprint wss://host:port/
//	bdlcap sample -out FILE
package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// version is reported to Wireshark and stored in capture files. Release builds
// replace it with an ldflag.
var version = "0.11.0"

const helpURL = "https://github.com/natebenes/bdlcap"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bdlcap:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "fingerprint":
			return cmdFingerprint(args[1:])
		case "sample":
			return cmdSample(args[1:])
		case "help":
			usage()
			return nil
		default:
			usage()
			os.Exit(2)
		}
	}
	return extcap(args)
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: bdlcap [--extcap-interfaces | --extcap-dlts | --extcap-config | --capture ...]
       bdlcap fingerprint [-sni NAME] wss://host:port/
       bdlcap sample -out FILE

bdlcap is a Wireshark extcap plugin. Wireshark supplies the --extcap-*
arguments; run "bdlcap --extcap-config --extcap-interface bdc" to list the
capture options it offers.

  fingerprint  show the certificate an endpoint presents and its fingerprint,
               for confirming it and setting --fingerprint
  sample       write a capture file holding one of each BDCC message, for
               checking the wireshark/bdc.lua dissector without a device`)
}

// newLogger returns the development logger. User-facing capture messages use
// the extcap control channel because Wireshark hides extcap stderr.
func newLogger(debug bool) *slog.Logger {
	level := slog.LevelWarn
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
