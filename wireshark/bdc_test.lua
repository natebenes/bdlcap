--
-- bdc_test.lua -- runs wireshark/bdc.lua outside Wireshark.
--
-- It stubs enough of the Wireshark Lua API to execute the dissector, reads the
-- capture written by "bdlcap sample", and checks that each message decodes to
-- the fields and sub-dissector handoff Annex YY calls for.
--
-- Usage:  lua5.4 wireshark/bdc_test.lua [capture.pcapng] [--inventory]
--
-- With --inventory it dissects any capture and prints a line per packet
-- instead of checking it against the sample's expectations.
--
-- Requires Lua 5.3 or later for string.unpack.
--

local capture = arg[1] or "bdc-sample.pcapng"
local inventory = false
for i = 1, #arg do
    if arg[i] == "--inventory" or arg[i] == "-i" then inventory = true end
end

--
-- Wireshark API stubs.
--

base = { NONE = 0, DEC = 1, HEX = 2, OCT = 3 }
wtap = {}
for i = 0, 15 do wtap["USER" .. i] = 45 + i end

expert = {
    group = { UNDECODED = 1, MALFORMED = 2, RESPONSE_CODE = 3 },
    severity = { NOTE = 1, WARN = 2, ERROR = 3 },
}

ProtoExpert = {}
function ProtoExpert.new(abbr, text) return { abbr = abbr, text = text } end

ProtoField = {}
local function field(kind)
    return function(abbr, name) return { abbr = abbr, name = name, kind = kind } end
end
for _, kind in ipairs({ "uint8", "uint16", "uint24", "uint32", "uint64", "bytes",
    "string", "ipv4", "ipv6", "bool" }) do
    ProtoField[kind] = field(kind)
end

function Proto(name, description)
    return { __isproto = true, name = name, description = description }
end

-- The dissector under test records what it did here.
local run = {}

local function reset_run()
    run = { fields = {}, experts = {}, calls = {}, info = "", protocol = "", cols = {} }
end

local function note_field(f, range, value)
    if value == nil and range then
        if f.kind == "bytes" or f.kind == "string" then
            value = range:tohex()
        elseif f.kind == "ipv4" or f.kind == "ipv6" then
            value = tostring(range:ipv4())
        else
            value = range:uint()
        end
    end
    run.fields[f.abbr] = value
    table.insert(run.fields, { abbr = f.abbr, value = value })
end

local TreeItem = {}
TreeItem.__index = TreeItem

local function new_item() return setmetatable({}, TreeItem) end

function TreeItem:add(what, range, value)
    if what and what.__isproto then
        return new_item()
    end
    note_field(what, range, value)
    return new_item()
end

TreeItem.add_le = TreeItem.add
function TreeItem:set_len() end
function TreeItem:append_text() end
function TreeItem:add_proto_expert_info(e) table.insert(run.experts, e.abbr) end

Dissector = {}
function Dissector.get(name)
    return {
        name = name,
        call = function(_, ...) table.insert(run.calls, name) end,
    }
end

DissectorTable = {}
local registered
function DissectorTable.get(name)
    return {
        add = function(_, encap, proto)
            registered = { table_name = name, encap = encap, proto = proto }
        end,
    }
end

--
-- Tvb and TvbRange.
--

local TvbRange = {}
TvbRange.__index = TvbRange

function new_tvb(data)
    local tvb = { data = data }
    function tvb:len() return #self.data end
    return setmetatable({}, {
        __index = tvb,
        __call = function(_, off, len)
            off = off or 0
            len = len or (#data - off)
            assert(off >= 0 and off + len <= #data,
                string.format("range %d..%d outside a buffer of %d octets", off, off + len, #data))
            return setmetatable({ s = data:sub(off + 1, off + len) }, TvbRange)
        end,
    })
end

function TvbRange:len() return #self.s end

function TvbRange:uint()
    local v = 0
    for i = 1, #self.s do v = v * 256 + self.s:byte(i) end
    return v
end

TvbRange.uint64 = TvbRange.uint

function TvbRange:tohex()
    return (self.s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

function TvbRange:string() return self.s end
function TvbRange:bytes() return self:tohex() end
function TvbRange:ipv4() return self:tohex() end
function TvbRange:ipv6() return self:tohex() end
function TvbRange:tvb() return new_tvb(self.s) end

--
-- pinfo.
--

local Column = {}
Column.__index = Column
function Column:append(s) run.info = run.info .. s end
function Column:set(s) run.info = s end
function Column:clear() run.info = "" end

local pinfo = { cols = setmetatable({}, {
    __index = function() return setmetatable({}, Column) end,
    __newindex = function(_, k, v)
        if k == "info" then
            run.info = v
        elseif k == "protocol" then
            run.protocol = v
        else
            run.cols[k] = v
        end
    end,
}) }

--
-- Load the dissector and recover it from its own registration.
--

local here = arg[0]:match("^(.*)[/\\][^/\\]*$") or "."
dofile(here .. "/bdc.lua")

assert(registered, "bdc.lua did not register a dissector")
assert(registered.table_name == "wtap_encap",
    "bdc.lua registered on " .. tostring(registered.table_name) .. ", want wtap_encap")
assert(registered.encap == wtap.USER15,
    "bdc.lua registered on encap " .. tostring(registered.encap) .. ", want wtap.USER15")
local bdc = registered.proto

--
-- Read the packets out of a pcapng file.
--

local function read_packets(path)
    local fh = assert(io.open(path, "rb"), "cannot open " .. path)
    local data = fh:read("a")
    fh:close()

    local packets, i = {}, 1
    while i + 11 <= #data do
        local btype = string.unpack("<I4", data, i)
        local total = string.unpack("<I4", data, i + 4)
        assert(total >= 12 and i + total - 1 <= #data,
            string.format("block at %d claims %d octets", i, total))
        if btype == 0x00000006 then -- enhanced packet block
            local caplen = string.unpack("<I4", data, i + 20)
            local origlen = string.unpack("<I4", data, i + 24)
            packets[#packets + 1] = {
                data = data:sub(i + 28, i + 28 + caplen - 1),
                origlen = origlen,
            }
        end
        i = i + total
    end
    return packets
end

--
-- Expectations, in the order "bdlcap sample" writes them.
--

local function has(list, want)
    for _, v in ipairs(list) do if v == want then return true end end
    return false
end

local expectations = {
    {
        name = "Acknowledge, ACK",
        fields = { ["bdc.function"] = 0x10 },
        info = "%(ACK%)",
        no_experts = true,
    },
    {
        name = "Frame, BACnet/SC",
        fields = { ["bdc.function"] = 0x11, ["bdc.network_type"] = 11, ["bdc.position"] = 0x10 },
        calls = { "bscvlc" },
        info = "port 3",
        dst = "01:02:03:04:05:06",
        src = "0a:0b:0c:0d:0e:0f",
    },
    {
        name = "Frame, BACnet/IP",
        fields = { ["bdc.network_type"] = 5, ["bdc.position"] = 0x01 },
        calls = { "bvlc" },
        dst = "192.168.1.20:47808",
        src = "192.168.1.10:47808",
    },
    {
        name = "Frame, MS/TP",
        fields = { ["bdc.network_type"] = 2 },
        calls = { "mstp" },
        dst = "0x0c",
        src = "0x05",
    },
    {
        name = "Frame, Ethernet",
        fields = { ["bdc.network_type"] = 0 },
        calls = { "bacnet" },
        dst = "00:11:22:33:44:55",
        src = "66:77:88:99:aa:bb",
    },
    {
        name = "Frame, truncated by the endpoint",
        fields = { ["bdc.original_length"] = 1500 },
        dst = "01:02:03:04:05:06",
        src = "0a:0b:0c:0d:0e:0f",
        experts = { "bdc.truncated" },
        calls = { "bscvlc" },
    },
    {
        name = "Connect, accepted",
        fields = { ["bdc.function"] = 0x13, ["bdc.peer.port"] = 47808 },
        info = "accepted",
    },
    {
        name = "Disconnect, closed by the device",
        fields = { ["bdc.function"] = 0x14, ["bdc.error.class"] = 7 },
        info = "closed by device",
    },
    {
        name = "Drop",
        fields = { ["bdc.function"] = 0x12, ["bdc.drop_count"] = 42 },
    },
    {
        name = "Acknowledge, NAK",
        fields = { ["bdc.function"] = 0x10, ["bdc.error.class"] = 1, ["bdc.error.code"] = 31 },
        experts = { "bdc.nak" },
        info = "%(NAK%)",
    },
}

--
-- Run.
--

local packets = read_packets(capture)

local function dissect(p)
    reset_run()
    local ok, err = pcall(bdc.dissector, new_tvb(p.data), pinfo, new_item())
    return ok, err
end

if inventory then
    for i, p in ipairs(packets) do
        local ok, err = dissect(p)
        if not ok then
            print(string.format("%3d  ERROR %s", i, tostring(err)))
        else
            local extra = ""
            if #run.calls > 0 then extra = extra .. "  -> " .. table.concat(run.calls, ",") end
            if #run.experts > 0 then extra = extra .. "  [" .. table.concat(run.experts, ",") .. "]" end
            if p.origlen > #p.data then
                extra = extra .. string.format("  (%d of %d octets)", #p.data, p.origlen)
            end
            local addrs = ""
            if run.cols.src or run.cols.dst then
                addrs = string.format("  %s -> %s", run.cols.src or "?", run.cols.dst or "?")
            end
            print(string.format("%3d  %-40s%s%s", i, run.info, addrs, extra))
        end
    end
    print(string.format("%d packets", #packets))
    os.exit(0)
end

local failures = 0
local function fail(fmt, ...)
    failures = failures + 1
    io.stderr:write("FAIL: " .. string.format(fmt, ...) .. "\n")
end

if #packets ~= #expectations then
    fail("%s holds %d packets, want %d", capture, #packets, #expectations)
end

for i, want in ipairs(expectations) do
    local p = packets[i]
    if not p then
        fail("%s: missing from the capture", want.name)
        goto continue
    end
    local ok, err = dissect(p)
    if not ok then
        fail("%s: dissector raised %s", want.name, tostring(err))
        goto continue
    end
    if run.protocol ~= "BDC" then
        fail("%s: protocol column = %q, want BDC", want.name, tostring(run.protocol))
    end
    for abbr, value in pairs(want.fields or {}) do
        if run.fields[abbr] == nil then
            fail("%s: field %s was not added", want.name, abbr)
        elseif run.fields[abbr] ~= value then
            fail("%s: field %s = %s, want %s", want.name, abbr,
                tostring(run.fields[abbr]), tostring(value))
        end
    end
    for _, e in ipairs(want.experts or {}) do
        if not has(run.experts, e) then
            fail("%s: expected expert info %s, got %s", want.name, e,
                #run.experts == 0 and "none" or table.concat(run.experts, ","))
        end
    end
    if want.no_experts and #run.experts > 0 then
        fail("%s: unexpected expert info %s", want.name, table.concat(run.experts, ","))
    end
    for _, c in ipairs(want.calls or {}) do
        if not has(run.calls, c) then
            fail("%s: expected a handoff to %s, got %s", want.name, c,
                #run.calls == 0 and "none" or table.concat(run.calls, ","))
        end
    end
    if want.calls and #run.calls ~= #want.calls then
        fail("%s: %d sub-dissector calls, want %d", want.name, #run.calls, #want.calls)
    end
    for _, col in ipairs({ "src", "dst" }) do
        if run.cols[col] ~= want[col] then
            fail("%s: %s column = %s, want %s", want.name, col,
                tostring(run.cols[col]), tostring(want[col]))
        end
    end
    if want.info and not run.info:match(want.info) then
        fail("%s: info column = %q, want it to match %q", want.name, run.info, want.info)
    end
    if has(run.experts, "bdc.malformed") then
        fail("%s: the dissector reported the message as malformed", want.name)
    end
    ::continue::
end

if failures > 0 then
    io.stderr:write(string.format("\n%d failure(s)\n", failures))
    os.exit(1)
end
print(string.format("ok  %d packets dissected from %s", #packets, capture))
