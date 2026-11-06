--
-- bdc.lua -- Wireshark dissector for BACnet Diagnostic Connection Control.
--
-- Decodes the BDCC messages of Annex YY (draft proposal 135-2024df) and hands
-- each captured frame to the dissector specified by Table YY-5.
--
-- Install by copying this file into a Wireshark plugin directory:
--   ~/.local/lib/wireshark/plugins/          (Linux)
--   %APPDATA%\Wireshark\plugins\             (Windows)
--
-- ENCAP must match the link type bdlcap writes (its --linktype option). Note
-- that Lua binds to WTAP_ENCAP values, which are not the LINKTYPE numbers
-- stored in the file: wtap.USER15 here is LINKTYPE_USER15, 162, there. This
-- registration also takes over Wireshark's built-in DLT_USER handling for the
-- slot, so pick one nothing else in the profile is using.
--
local ENCAP = wtap.USER15

local bdc = Proto("bdc", "BACnet Diagnostic Connection Control")

-- Table YY-1.
local FN_CAPTURE, FN_MONITOR = 0x00, 0x01
local FN_ACKNOWLEDGE, FN_FRAME, FN_DROP = 0x10, 0x11, 0x12
local FN_CONNECT, FN_DISCONNECT = 0x13, 0x14

local functions = {
    [FN_CAPTURE] = "Capture",
    [FN_MONITOR] = "Monitor",
    [FN_ACKNOWLEDGE] = "Acknowledge",
    [FN_FRAME] = "Frame",
    [FN_DROP] = "Drop",
    [FN_CONNECT] = "Connect",
    [FN_DISCONNECT] = "Disconnect",
}

-- BACnetNetworkType, Clause 21.
local network_types = {
    [0] = "ethernet", [1] = "arcnet", [2] = "mstp", [3] = "ptp", [4] = "lontalk",
    [5] = "ipv4", [6] = "zigbee", [7] = "virtual", [9] = "ipv6", [10] = "serial",
    [11] = "secure-connect",
}

-- The frame contents of Table YY-5, as Wireshark dissector names. Anything else
-- uses the raw-data dissector, including PTP, which Wireshark does not decode.
local dissector_for = {
    [0] = "bacnet",  -- Ethernet carries a bare NPDU
    [1] = "bacnet",  -- ARCNET likewise
    [2] = "mstp",
    [5] = "bvlc",
    [7] = "bacnet",  -- virtual, which Table YY-5 does not list; assumed an NPDU
    [9] = "bvlc",
    [11] = "bscvlc",
}

-- Table YY-3.
local positions = { [0x10] = "receive", [0x01] = "transmit", [0x11] = "both" }

local error_classes = { [1] = "OBJECT", [5] = "SERVICES", [7] = "COMMUNICATION" }
local error_codes = {
    [0] = "OTHER", [7] = "INCONSISTENT_PARAMETERS", [31] = "UNKNOWN_OBJECT",
    [45] = "OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED", [80] = "PARAMETER_OUT_OF_RANGE",
}

local host_kinds = { [0] = "none", [1] = "ip-address", [2] = "name" }

local filter_choices = {
    [0] = "source-mac", [1] = "destination-mac", [2] = "datalink-message-type",
    [3] = "network-message-type", [4] = "apdu-type", [5] = "confirmed-service-choice",
    [6] = "unconfirmed-service-choice", [7] = "logical-not", [8] = "logical-and",
    [9] = "logical-or",
}

local f = {
    fn = ProtoField.uint8("bdc.function", "Function", base.HEX, functions),
    timestamp = ProtoField.uint64("bdc.timestamp", "Timestamp", base.DEC, nil, nil,
        "Microseconds since an epoch chosen by the diagnostic endpoint"),
    port = ProtoField.uint24("bdc.network_port", "Network port", base.DEC, nil, nil,
        "Instance number of the Network Port object"),
    nettype = ProtoField.uint8("bdc.network_type", "Network type", base.DEC, network_types),
    position = ProtoField.uint8("bdc.position", "Capture position", base.HEX, positions),
    origlen = ProtoField.uint32("bdc.original_length", "Original length", base.DEC, nil, nil,
        "Length of the captured frame before any truncation"),
    dstlen = ProtoField.uint8("bdc.dest_mac_len", "Destination MAC length", base.DEC),
    dst = ProtoField.bytes("bdc.dest_mac", "Destination MAC"),
    srclen = ProtoField.uint8("bdc.src_mac_len", "Source MAC length", base.DEC),
    src = ProtoField.bytes("bdc.src_mac", "Source MAC"),
    data = ProtoField.bytes("bdc.frame_data", "Frame data"),

    mask = ProtoField.uint8("bdc.mask", "Diagnostic mask", base.HEX),
    mask_accepted = ProtoField.bool("bdc.mask.accepted", "Accepted connections", 8, nil, 0x04),
    mask_rejected = ProtoField.bool("bdc.mask.rejected", "Rejected connections", 8, nil, 0x02),
    mask_disconnect = ProtoField.bool("bdc.mask.disconnect", "Disconnections", 8, nil, 0x01),

    drops = ProtoField.uint32("bdc.drop_count", "Frames dropped", base.DEC),

    err_class = ProtoField.uint32("bdc.error.class", "Error class", base.DEC, error_classes),
    err_code = ProtoField.uint32("bdc.error.code", "Error code", base.DEC, error_codes),

    peer_kind = ProtoField.uint8("bdc.peer.host_kind", "Host", base.DEC, host_kinds),
    peer_ipv4 = ProtoField.ipv4("bdc.peer.ipv4", "Peer address"),
    peer_ipv6 = ProtoField.ipv6("bdc.peer.ipv6", "Peer address"),
    peer_host = ProtoField.bytes("bdc.peer.host", "Peer address"),
    peer_name = ProtoField.string("bdc.peer.name", "Peer name"),
    peer_port = ProtoField.uint16("bdc.peer.port", "Peer port", base.DEC),
    peer_san = ProtoField.string("bdc.peer.san", "Subject alternative name"),
    peer_fp = ProtoField.bytes("bdc.peer.key_fingerprint", "Key fingerprint (SHA-256)"),

    filter_mac = ProtoField.bytes("bdc.filter.mac", "MAC address"),
    filter_value = ProtoField.uint32("bdc.filter.value", "Value", base.DEC),
}
bdc.fields = f

local ef_truncated = ProtoExpert.new("bdc.truncated",
    "The endpoint truncated this LPDU to fit the WebSocket message",
    expert.group.UNDECODED, expert.severity.NOTE)
local ef_malformed = ProtoExpert.new("bdc.malformed",
    "Malformed BDCC message", expert.group.MALFORMED, expert.severity.ERROR)
local ef_nak = ProtoExpert.new("bdc.nak",
    "The diagnostic endpoint refused the request", expert.group.RESPONSE_CODE,
    expert.severity.WARN)
bdc.experts = { ef_truncated, ef_malformed, ef_nak }

-- sub returns a sub-dissector by name, or nil when this build has none.
local cache = {}
local function sub(name)
    if cache[name] == nil then
        local ok, d = pcall(Dissector.get, name)
        cache[name] = ok and d or false
    end
    return cache[name] or nil
end

-- ipv6_text formats the 16 octets at off in the RFC 5952 text form.
local function ipv6_text(tvb, off)
    local groups = {}
    for i = 0, 7 do groups[i + 1] = tvb(off + 2 * i, 2):uint() end
    -- Find the longest run of two or more zero groups, the first if tied.
    local best, best_len, run_start = nil, 1, nil
    for i = 1, 9 do
        if i <= 8 and groups[i] == 0 then
            run_start = run_start or i
        elseif run_start then
            if i - run_start > best_len then best, best_len = run_start, i - run_start end
            run_start = nil
        end
    end
    local function hex(from, to)
        local parts = {}
        for i = from, to do parts[#parts + 1] = string.format("%x", groups[i]) end
        return table.concat(parts, ":")
    end
    if not best then return hex(1, 8) end
    return hex(1, best - 1) .. "::" .. hex(best + best_len, 8)
end

-- mac_text formats the n-octet MAC address at off for the Source and
-- Destination columns. A BACnet/IP MAC is an IPv4 address and UDP port
-- (Annex J), and a BACnet/IPv6 MAC an IPv6 address and UDP port (Annex U).
local function mac_text(tvb, off, n, nettype)
    if nettype == 5 and n == 6 then
        return string.format("%d.%d.%d.%d:%d", tvb(off, 1):uint(), tvb(off + 1, 1):uint(),
            tvb(off + 2, 1):uint(), tvb(off + 3, 1):uint(), tvb(off + 4, 2):uint())
    end
    if nettype == 9 and n == 18 then
        return string.format("[%s]:%d", ipv6_text(tvb, off), tvb(off + 16, 2):uint())
    end
    -- One-octet MS/TP and ARCNET stations, as Wireshark's mstp dissector shows them.
    if n == 1 then return string.format("0x%02x", tvb(off, 1):uint()) end
    local octets = {}
    for i = 0, n - 1 do octets[#octets + 1] = string.format("%02x", tvb(off + i, 1):uint()) end
    return table.concat(octets, ":")
end

--
-- Clause 20.2 tag reading, for the variable-length fields.
--

-- read_tag returns a table describing the tag at off, or nil past the end.
local function read_tag(tvb, off)
    if off >= tvb:len() then return nil end
    local first = tvb(off, 1):uint()
    local lower = first % 16
    local t = {
        number = math.floor(first / 16),
        context = lower >= 8,
        hdrlen = 1,
        length = 0,
    }
    local lvt = lower % 8
    if t.number == 0x0F then
        if off + 1 >= tvb:len() then return nil end
        t.number = tvb(off + 1, 1):uint()
        t.hdrlen = t.hdrlen + 1
    end
    if lvt == 6 then
        t.opening = true
    elseif lvt == 7 then
        t.closing = true
    elseif lvt == 5 then
        local at = off + t.hdrlen
        if at >= tvb:len() then return nil end
        local n = tvb(at, 1):uint()
        if n < 254 then
            t.length, t.hdrlen = n, t.hdrlen + 1
        elseif n == 254 then
            if at + 2 >= tvb:len() then return nil end
            t.length, t.hdrlen = tvb(at + 1, 2):uint(), t.hdrlen + 3
        else
            if at + 4 >= tvb:len() then return nil end
            t.length, t.hdrlen = tvb(at + 1, 4):uint(), t.hdrlen + 5
        end
    else
        t.length = lvt
    end
    if off + t.hdrlen + t.length > tvb:len() then return nil end
    t.value_off = off + t.hdrlen
    t.next = off + t.hdrlen + t.length
    return t
end

-- dissect_error decodes the two application-tagged enumerated values of a
-- BACnetError and returns the offset past them.
local function dissect_error(tvb, off, tree)
    local start = off
    local sub_tree = tree:add(bdc, tvb(off), "Error")
    for _, field in ipairs({ f.err_class, f.err_code }) do
        local t = read_tag(tvb, off)
        if not t or t.context or t.number ~= 9 or t.length == 0 then
            sub_tree:add_proto_expert_info(ef_malformed)
            return tvb:len()
        end
        sub_tree:add(field, tvb(t.value_off, t.length))
        off = t.next
    end
    sub_tree:set_len(off - start)
    return off
end

-- dissect_peer decodes a BACnetCapturePeer, stopping at the first octet that
-- is not one of its context tags -- which is where an optional BACnetError
-- begins.
local function dissect_peer(tvb, off, tree)
    local start = off
    local sub_tree = tree:add(bdc, tvb(off), "Peer")

    local t = read_tag(tvb, off)
    if not t or not t.context or not t.opening or t.number ~= 0 then
        sub_tree:add_proto_expert_info(ef_malformed)
        return tvb:len(), nil
    end
    off = start + t.hdrlen

    -- host [0] BACnetHostAddress, itself a CHOICE and so wrapped in its own
    -- opening and closing tags.
    local ht = read_tag(tvb, off)
    if not ht or not ht.context or not ht.opening or ht.number ~= 0 then
        sub_tree:add_proto_expert_info(ef_malformed)
        return tvb:len(), nil
    end
    off = off + ht.hdrlen

    local label
    local ct = read_tag(tvb, off)
    if not ct or not ct.context then
        sub_tree:add_proto_expert_info(ef_malformed)
        return tvb:len(), nil
    end
    sub_tree:add(f.peer_kind, tvb(off, 1), ct.number)
    if ct.number == 1 and ct.length == 4 then
        sub_tree:add(f.peer_ipv4, tvb(ct.value_off, 4))
        label = tostring(tvb(ct.value_off, 4):ipv4())
    elseif ct.number == 1 and ct.length == 16 then
        sub_tree:add(f.peer_ipv6, tvb(ct.value_off, 16))
        label = tostring(tvb(ct.value_off, 16):ipv6())
    elseif ct.number == 1 then
        sub_tree:add(f.peer_host, tvb(ct.value_off, ct.length))
    elseif ct.number == 2 and ct.length > 1 then
        -- The first content octet is the character set.
        sub_tree:add(f.peer_name, tvb(ct.value_off + 1, ct.length - 1))
        label = tvb(ct.value_off + 1, ct.length - 1):string()
    end
    off = ct.next

    local closing = read_tag(tvb, off)
    if closing and closing.closing then off = off + closing.hdrlen end

    -- port [1] Unsigned16
    local pt = read_tag(tvb, off)
    if pt and pt.context and pt.number == 1 and pt.length > 0 and not pt.opening then
        sub_tree:add(f.peer_port, tvb(pt.value_off, pt.length))
        if label then label = label .. ":" .. tvb(pt.value_off, pt.length):uint() end
        off = pt.next
    end

    local outer = read_tag(tvb, off)
    if outer and outer.closing then off = off + outer.hdrlen end

    -- The optional subject alternative name and key fingerprint.
    while true do
        local ot = read_tag(tvb, off)
        if not ot or not ot.context or ot.opening or ot.closing then break end
        if ot.number == 1 and ot.length > 1 then
            sub_tree:add(f.peer_san, tvb(ot.value_off + 1, ot.length - 1))
        elseif ot.number == 2 then
            sub_tree:add(f.peer_fp, tvb(ot.value_off, ot.length))
        else
            break
        end
        off = ot.next
    end

    sub_tree:set_len(off - start)
    if label then sub_tree:append_text(", " .. label) end
    return off, label
end

-- dissect_filter decodes one BACnetCaptureFilter and returns the offset past
-- it. bdlcap does not record the requests it sends, but another tool's capture
-- may, and this keeps bdc.lua a complete Annex YY dissector.
local function dissect_filter(tvb, off, tree)
    local t = read_tag(tvb, off)
    if not t or not t.context then
        tree:add_proto_expert_info(ef_malformed)
        return tvb:len()
    end
    local name = filter_choices[t.number] or ("choice " .. t.number)

    if t.number <= 1 then
        local node = tree:add(bdc, tvb(off, t.hdrlen + t.length), name)
        node:add(f.filter_mac, tvb(t.value_off, t.length))
        return t.next
    end
    if t.number <= 6 then
        local node = tree:add(bdc, tvb(off, t.hdrlen + t.length), name)
        if t.length > 0 then
            node:add(f.filter_value, tvb(t.value_off, t.length))
            node:append_text(" = " .. tvb(t.value_off, t.length):uint())
        end
        return t.next
    end
    if t.number == 7 then
        local node = tree:add(bdc, tvb(off), name)
        local at = dissect_filter(tvb, off + t.hdrlen, node)
        local closing = read_tag(tvb, at)
        if closing and closing.closing then at = at + closing.hdrlen end
        node:set_len(at - off)
        return at
    end
    if t.number == 8 or t.number == 9 then
        local node = tree:add(bdc, tvb(off), name)
        local at = off + t.hdrlen
        for _, side in ipairs({ "left", "right" }) do
            local ot = read_tag(tvb, at)
            if not ot or not ot.opening then
                node:add_proto_expert_info(ef_malformed)
                return tvb:len()
            end
            local operand = node:add(bdc, tvb(at), side)
            local inner = dissect_filter(tvb, at + ot.hdrlen, operand)
            local closing = read_tag(tvb, inner)
            if closing and closing.closing then inner = inner + closing.hdrlen end
            operand:set_len(inner - at)
            at = inner
        end
        local closing = read_tag(tvb, at)
        if closing and closing.closing then at = at + closing.hdrlen end
        node:set_len(at - off)
        return at
    end
    tree:add(bdc, tvb(off, t.hdrlen + t.length), name)
    return t.next
end

function bdc.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 1 then return 0 end

    pinfo.cols.protocol = "BDC"
    local fn = tvb(0, 1):uint()
    local name = functions[fn] or string.format("Function 0x%02X", fn)
    local t = tree:add(bdc, tvb(), "BACnet Diagnostic Connection Control, " .. name)
    t:add(f.fn, tvb(0, 1))
    pinfo.cols.info = name

    local off = 1
    local function need(n)
        if off + n > len then
            t:add_proto_expert_info(ef_malformed)
            return false
        end
        return true
    end

    -- Timestamp, then the network port and its network type, in the messages
    -- that carry them.
    if fn == FN_FRAME or fn == FN_CONNECT or fn == FN_DISCONNECT then
        if not need(8) then return len end
        t:add(f.timestamp, tvb(off, 8))
        off = off + 8
    end
    if fn == FN_FRAME or fn == FN_CONNECT or fn == FN_DISCONNECT
        or fn == FN_CAPTURE or fn == FN_MONITOR then
        if not need(3) then return len end
        t:add(f.port, tvb(off, 3))
        pinfo.cols.info:append(string.format(" port %d", tvb(off, 3):uint()))
        off = off + 3
    end
    local nettype
    if fn == FN_FRAME or fn == FN_CONNECT or fn == FN_DISCONNECT then
        if not need(1) then return len end
        nettype = tvb(off, 1):uint()
        t:add(f.nettype, tvb(off, 1))
        off = off + 1
    end

    if fn == FN_FRAME then
        if not need(1) then return len end
        t:add(f.position, tvb(off, 1))
        pinfo.cols.info:append(" " .. (positions[tvb(off, 1):uint()] or "?"))
        off = off + 1

        if not need(4) then return len end
        local original = tvb(off, 4):uint()
        local origlen_item = t:add(f.origlen, tvb(off, 4))
        off = off + 4

        local addrs = {}
        for _, pair in ipairs({ { f.dstlen, f.dst }, { f.srclen, f.src } }) do
            if not need(1) then return len end
            local n = tvb(off, 1):uint()
            t:add(pair[1], tvb(off, 1))
            off = off + 1
            if n > 0 then
                if not need(n) then return len end
                t:add(pair[2], tvb(off, n))
                addrs[#addrs + 1] = mac_text(tvb, off, n, nettype)
                off = off + n
            else
                addrs[#addrs + 1] = false
            end
        end

        -- Fill the address columns as text rather than through pinfo.src and
        -- pinfo.dst: Wireshark's address types cannot carry the UDP port of a
        -- BACnet/IP MAC. Set them before the handoff so they survive a
        -- sub-dissector that throws on a malformed frame.
        if addrs[1] then pinfo.cols.dst = addrs[1] end
        if addrs[2] then pinfo.cols.src = addrs[2] end

        -- Frame Data has no explicit length; it is the rest of the message.
        local remaining = len - off
        if remaining > 0 then
            t:add(f.data, tvb(off, remaining))
        end
        if original > remaining then
            origlen_item:add_proto_expert_info(ef_truncated)
            origlen_item:append_text(string.format(" (%d octets captured)", remaining))
        end
        if remaining > 0 then
            local d = sub(dissector_for[nettype] or "data")
            if d then
                d:call(tvb(off, remaining):tvb(), pinfo, tree)
            end
        end
        return len
    end

    if fn == FN_MONITOR then
        if not need(1) then return len end
        local m = t:add(f.mask, tvb(off, 1))
        m:add(f.mask_accepted, tvb(off, 1))
        m:add(f.mask_rejected, tvb(off, 1))
        m:add(f.mask_disconnect, tvb(off, 1))
        return len
    end

    if fn == FN_CAPTURE then
        if not need(1) then return len end
        t:add(f.position, tvb(off, 1))
        off = off + 1
        if off < len then
            dissect_filter(tvb, off, t)
        end
        return len
    end

    if fn == FN_DROP then
        if not need(4) then return len end
        t:add(f.drops, tvb(off, 4))
        pinfo.cols.info:append(string.format(", %d frames", tvb(off, 4):uint()))
        return len
    end

    if fn == FN_CONNECT or fn == FN_DISCONNECT then
        local label
        off, label = dissect_peer(tvb, off, t)
        if label then pinfo.cols.info:append(", " .. label) end
        if off < len then
            -- On a Connect the error means the device rejected the peer; on a
            -- Disconnect it means the device closed the connection.
            off = dissect_error(tvb, off, t)
            pinfo.cols.info:append(fn == FN_CONNECT and ", rejected" or ", closed by device")
        else
            pinfo.cols.info:append(fn == FN_CONNECT and ", accepted" or ", closed by peer")
        end
        return len
    end

    if fn == FN_ACKNOWLEDGE then
        -- The presence of the error indicates a NAK, its absence an ACK.
        if off < len then
            local at = dissect_error(tvb, off, t)
            t:add_proto_expert_info(ef_nak)
            pinfo.cols.info:append(" (NAK)")
            off = at
        else
            pinfo.cols.info:append(" (ACK)")
        end
        return len
    end

    return len
end

DissectorTable.get("wtap_encap"):add(ENCAP, bdc)
