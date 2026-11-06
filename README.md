# bdlcap

A **Wireshark extcap plugin** that captures BACnet traffic from a device's
**BACnet Diagnostic Endpoint**, as defined by Annex YY of proposal 135-2024df. It
connects to the endpoint over `wss`, asks the device to mirror link-layer
traffic and connection diagnostics, and streams the result into Wireshark.

> [!WARNING]
> `bdlcap` is an unsupported experiment published only to help reviewers and
> implementers test interoperability with 135-2024df. It is not a reference
> implementation, has no compatibility or support commitment, and should not be
> treated as production-supported software. Annex YY is still a proposal, and
> this tool may change with it.

135-2024df has been approved for publication public review (PPR). Comments on
the proposal belong in that review rather than in this repository's issues.
Issues are for bugs in the tool itself, with no promise of a fix.

**It works with every BACnet data link, not just BACnet/SC.** The device itself
exports the frames over an ordinary secure WebSocket, so all you need is a network
path to the device, rather than a physical position on the network being captured.
That makes captures possible that used to be difficult or impossible:

- **Remote capture of MS/TP**, from a device's MS/TP port, with no one on site and
  no RS-485 adapter.
- **Capture from a BACnet/SC hub hosted in the cloud**, where there is no switch
  to attach a SPAN port or TAP to.
- **BACnet/SC in the clear**, without weakening its encryption. The traffic cannot
  be read off the wire, but the device can see it and export it.
- **BACnet/IP and BACnet/IPv6 from the device's point of view**, without having to
  find the right switch port.

## Binaries

- **`bdlcap`** — the extcap plugin. Wireshark invokes it with the `--extcap-*`
  arguments. `bdlcap fingerprint` shows the certificate an endpoint presents, and
  `bdlcap sample` writes a capture file holding one of every message a diagnostic
  endpoint can send, for checking the dissector without a device.

## Installing

Download the archive for your platform from the
[GitHub releases](https://github.com/natebenes/bdlcap/releases). Each archive
contains both the `bdlcap` executable and the required `bdc.lua` dissector.

On Linux, extract the archive and install both files:

```sh
install -D bdlcap ~/.local/lib/wireshark/extcap/bdlcap
install -D bdc.lua ~/.local/lib/wireshark/plugins/bdc.lua
```

On macOS, create the directories first because its `install` command does not
support `-D`:

```sh
mkdir -p ~/.local/lib/wireshark/extcap ~/.local/lib/wireshark/plugins
install bdlcap ~/.local/lib/wireshark/extcap/bdlcap
install bdc.lua ~/.local/lib/wireshark/plugins/bdc.lua
```

On Windows, copy `bdlcap.exe` to `%APPDATA%\Wireshark\extcap\` and `bdc.lua`
to `%APPDATA%\Wireshark\plugins\`.

To build from source on Linux instead, use Go 1.27.3 or newer:

```sh
go build -o bdlcap ./cmd/bdlcap
install -D bdlcap            ~/.local/lib/wireshark/extcap/bdlcap
install -D wireshark/bdc.lua ~/.local/lib/wireshark/plugins/bdc.lua
```

For a Windows source build, cross-compile and copy both files into the
Wireshark profile:

```sh
GOOS=windows GOARCH=amd64 go build -o bdlcap.exe ./cmd/bdlcap
#  -> %APPDATA%\Wireshark\extcap\bdlcap.exe
#  -> %APPDATA%\Wireshark\plugins\bdc.lua
```

"BACnet Diagnostic Connection" then appears in Wireshark's interface list. Its
configuration takes the endpoint URI, the credentials, how to verify the
endpoint's certificate, and what to capture.

## Connecting to an endpoint

Use one of the URIs in the device's `Diagnostic_Endpoint_URIs` property. `bdlcap`
does not read it from the device for you.

### Credentials

Annex YY authenticates tools solely by HTTP Basic (YY.5.3, YY.5.4), and `bdlcap`
presents no client certificate. Set `--username` and `--password`, or leave both
empty for an endpoint that does not require authentication.

- Credentials are sent on the first handshake, once the endpoint's certificate
  has been verified. A 401 ends the capture rather than being retried, so
  rejected credentials cannot lock an account.
- Redirects are not followed, so credentials reach only the configured endpoint.
- `--uri` must not contain credentials, because it is recorded in the capture file.

> [!CAUTION]
> Wireshark passes extcap options on the command line, so **the password is
> visible to other local users in the process list** during a capture. Avoid
> shared machines, and use an account limited to diagnostics.

### Verifying the endpoint

Annex YY leaves the endpoint's certificate as a local matter, so choose the check
that fits the device. Only one of these options may be set.

| Option | The endpoint's certificate must | Use for |
|---|---|---|
| *(none)* | Chain to a system root and match the hostname | A publicly trusted certificate |
| `--ca FILE` | Chain to a certificate in the PEM file and match the hostname | A private CA, or a self-signed certificate with a matching name |
| `--fingerprint HEX` | Have exactly this SHA-256 fingerprint; chain, name, and dates are not checked | A self-signed or factory certificate with no usable name |
| `--insecure` | Nothing: an impostor could receive the credentials and fake the capture | A last resort on a network you trust |

`--sni` changes the name that is sent and verified, for a device reached by an
address its certificate does not name.

To see the certificate an endpoint presents, run `bdlcap fingerprint` from wherever
you installed it:

```sh
~/.local/lib/wireshark/extcap/bdlcap fingerprint wss://device.example.com:47810/
```

This completes only a TLS handshake, so it sends no credentials, and it prints the
certificate's names, dates, and fingerprint. It verifies nothing, and anyone able
to intercept the connection could answer it, so confirm the fingerprint with the
device or its administrator before pinning it. A failed verification during a
capture reports the same fingerprint.

Capture files hold traffic in the clear, including BACnet/SC traffic that was
encrypted on the wire, so handle them as you would the network itself.

## Capture filters

Annex YY filters are boolean expressions evaluated at the capture point, not
BPF. `bdlcap` compiles a small syntax into a `BACnetCaptureFilter`:

```
expr      := orExpr
orExpr    := andExpr ( "or" andExpr )*
andExpr   := unary ( "and" unary )*
unary     := "not" unary | "(" expr ")" | predicate
predicate := "all"
           | "src" mac | "dst" mac
           | "dlmsg" uint | "netmsg" uint | "apdu" uint
           | "confirmed" uint | "unconfirmed" uint
mac       := hex octets, optionally ':' or '-' separated, or '#' followed by a
             decimal value for a one-octet address
```

`and` binds tighter than `or`, both associate to the left, and numbers are
decimal unless prefixed `0x`. An MS/TP station address may be written `0c` or
`#12`.

```
all
src #12 or dst #12
apdu 0 and confirmed 15
not (dlmsg 0x0a)
```

Wireshark's own capture filter box, when used, supplies the expression instead.

## Capture files

Every packet in the capture is one **endpoint-to-tool BDCC message, verbatim**:
frames, and also the `Connect`, `Disconnect`, `Drop`, and `Acknowledge` events,
in timeline order with the traffic that surrounds them. Nothing is re-encoded
and no pseudo-header is added, so the file is a faithful recording of the
diagnostic connection.

There is no registered link type for that yet, so the file uses a private-use
one — `LINKTYPE_USER15` (162) by default, selectable across USER0..USER15.
`wireshark/bdc.lua` decodes the messages and hands each captured frame to the
dissector implied by the network type (Table YY-5):

| Network type | Frame contents | Dissector |
|---|---|---|
| mstp | MS/TP frame | `mstp` |
| ipv4, ipv6 | BVLC message | `bvlc` |
| secure-connect | BVLC message | `bscvlc` |
| ethernet, arcnet | BACnet NPDU | `bacnet` |
| virtual | BACnet NPDU, which is this tool's assumption | `bacnet` |
| ptp | PTP frame, which Wireshark does not decode | `data` |
| lontalk, zigbee, serial | Not listed in Table YY-5 | `data` |

If you change the link type, change `ENCAP` at the top of `bdc.lua` to match.
Note that Lua binds to `WTAP_ENCAP` values rather than the `LINKTYPE` numbers
stored in the file, and that registering there displaces Wireshark's built-in
DLT_USER handling for that slot.

## Development

```sh
go test ./... -race
go test ./internal/wire -fuzz FuzzDecode -fuzztime 60s

# The dissector, without Wireshark: stubs the Wireshark Lua API, reads a
# capture, and checks the fields and sub-dissector handoffs of every message.
# Needs Lua 5.3 or later for string.unpack.
go run ./cmd/bdlcap sample -out /tmp/bdc-sample.pcapng
lua5.4 wireshark/bdc_test.lua /tmp/bdc-sample.pcapng

# The same harness will dissect any capture and summarise it, which is the
# quickest way to see what a device actually sent.
lua5.4 wireshark/bdc_test.lua real-capture.pcapng --inventory
```

The extcap query modes are pure output and can be checked by hand:

```sh
./bdlcap --extcap-interfaces
./bdlcap --extcap-dlts   --extcap-interface bdc
./bdlcap --extcap-config --extcap-interface bdc
```

Package layout: `internal/wire` is the wire format, computational only, and
holds the capture filter syntax; `internal/bdc` is the connection — dial,
install, receive, keepalive; `internal/pcapng` writes the capture stream;
`internal/pki` builds the TLS configuration; `cmd/bdlcap` is the extcap
interface; `wireshark/bdc.lua` is the dissector.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

This source code is available under the [Mozilla Public License 2.0](LICENSE).

BACnet is a registered trademark of ASHRAE. This project is not an ASHRAE
publication and is not endorsed by ASHRAE.

## Infrequently asked questions

**Why is it called `bdlcap`?** Old versions of the proposal called this the BACnet
Diagnostic *Link*. Also, say it out loud: it sounds like "bottlecap".
