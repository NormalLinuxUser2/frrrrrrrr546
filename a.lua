local SCANNER_VERSION = "1.1.0"

--==================================================================
-- Utility
--==================================================================

local function safe(fn, ...)
    local ok, res = pcall(fn, ...)
    if ok then return true, res end
    return false, tostring(res)
end

local function safeType(v)
    local ok, t = pcall(type, v)
    if not ok then return "?" end
    return t
end

local function typedesc(v)
    local t = safeType(v)
    if t ~= "function" then return t end
    local isC = rawget(getfenv(0), "iscclosure")
    if type(isC) == "function" then
        local ok, r = pcall(isC, v)
        if ok then return r and "cfunction" or "lfunction" end
    end
    return "function"
end

local function randStr()
    local buf = {}
    for i = 1, 12 do
        buf[i] = string.char(math.random(97, 122))
    end
    return table.concat(buf)
end

math.randomseed((tick() * 1e6) % 2147483647)

-- Resolve a possibly dotted name (e.g. "syn.messagebox") against the global
-- environment, falling back through getgenv/_G. Returns the value or nil.
local function resolveGlobal(name)
    local roots = { _G }
    if type(getgenv) == "function" then
        local ok, g = pcall(getgenv); if ok and type(g) == "table" then table.insert(roots, 1, g) end
    end
    for _, root in ipairs(roots) do
        local v = root
        local ok = true
        for part in string.gmatch(name, "[^%.]+") do
            if type(v) ~= "table" and type(v) ~= "userdata" then ok = false; break end
            local okIdx, nv = pcall(function() return v[part] end)
            if not okIdx then ok = false; break end
            v = nv
        end
        if ok and v ~= nil then return v end
    end
    return nil
end

-- Find the first present name from a list; returns value, matched-name.
local function firstGlobal(names)
    for _, n in ipairs(names) do
        local v = resolveGlobal(n)
        if v ~= nil then return v, n end
    end
    return nil, nil
end

-- Metadata for a function value (type, arity, source, address string).
local function fnMeta(v)
    local entry = { type = typedesc(v) }
    if entry.type == "cfunction" or entry.type == "lfunction" or entry.type == "function" then
        local okA, a = pcall(debug.info, v, "a"); if okA then entry.arity = tostring(a) end
        local okS, s = pcall(debug.info, v, "s"); if okS then entry.source = tostring(s) end
        entry.addr = tostring(v)
    end
    return entry
end

local function fnvHash(str)
    local h = 2166136261
    for i = 1, #str do
        h = (h ~ string.byte(str, i)) & 0xFFFFFFFF
        h = (h * 16777619) & 0xFFFFFFFF
    end
    return string.format("%08x", h)
end

-- Own serializer (pseudo-JSON, stable key order, cycle-safe)
local function serialize(v, indent, seen, maxDepth)
    indent = indent or 0
    seen = seen or {}
    maxDepth = maxDepth or 12
    local pad = string.rep("  ", indent)
    local t = safeType(v)
    if t == "nil" then return "null" end
    if t == "boolean" then return tostring(v) end
    if t == "number" then
        if v ~= v then return '"NaN"' end
        if v == math.huge then return '"Infinity"' end
        if v == -math.huge then return '"-Infinity"' end
        return tostring(v)
    end
    if t == "string" then
        return string.format("%q", v):gsub("\\\n", "\\n")
    end
    if t == "function" or t == "userdata" or t == "thread" then
        return string.format('"<%s: %s>"', t, tostring(v):gsub('"', "'"))
    end
    if t ~= "table" then
        return string.format('"<%s>"', t)
    end
    if seen[v] then return '"<cycle>"' end
    if indent >= maxDepth then return '"<max-depth>"' end
    seen[v] = true

    -- collect + sort keys
    local keys = {}
    local isArray = true
    local n = 0
    for k in pairs(v) do
        keys[#keys + 1] = k
        n = n + 1
        if safeType(k) ~= "number" then isArray = false end
    end
    if n == 0 then seen[v] = nil; return "{}" end
    if isArray then
        table.sort(keys)
        local parts = {}
        for i, k in ipairs(keys) do
            parts[i] = pad .. "  " .. serialize(v[k], indent + 1, seen, maxDepth)
        end
        seen[v] = nil
        return "[\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "]"
    else
        table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
        local parts = {}
        for i, k in ipairs(keys) do
            local ks = string.format("%q", tostring(k))
            parts[i] = pad .. "  " .. ks .. ": " .. serialize(v[k], indent + 1, seen, maxDepth)
        end
        seen[v] = nil
        return "{\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "}"
    end
end

--==================================================================
-- Report skeleton
--==================================================================

local report = {
    meta = {},
    executor = {},
    roblox = {},
    api = {},
    fs_probes = {},
    shell = {},
    persistence = {},
    clipboard = {},
    memory = {},
    gc_scan = {},
    native = {},
    native_call = {},   -- Tier B: primitives to build a MessageBoxA call
    vm_corruption = {},  -- Tier C: VM-internals write access
    buffers = {},        -- Luau buffer memory-corruption surface
    ptr_leaks = {},      -- address disclosure
    exploit_assessment = {}, -- ranked verdict, consumes everything above
    env = {},
    errors = {},
}

local function err(section, msg)
    report.errors[section] = report.errors[section] or {}
    table.insert(report.errors[section], tostring(msg))
end

--==================================================================
-- 0. Meta
--==================================================================

do
    report.meta.scanner_version = SCANNER_VERSION
    local ok, t = safe(function()
        return DateTime.now():ToIsoDate()
    end)
    report.meta.timestamp = ok and t or tostring(os.time and os.time() or tick())
    report.meta.script_hash = fnvHash(SCANNER_VERSION .. tostring(tick()))
end

--==================================================================
-- 1. Executor fingerprint
--==================================================================

do
    local genv = _G
    local ok, g = pcall(getgenv); if ok and type(g) == "table" then genv = g end

    local name, ver = "unknown", "unknown"
    local ok1, n = safe(function() return identifyexecutor() end)
    if ok1 and type(n) == "string" then name = n end
    if ok1 and type(n) == "table" then name = tostring(n[1] or "?"); ver = tostring(n[2] or "?") end
    if name == "unknown" then
        local ok2, n2 = safe(function() return getexecutorname() end)
        if ok2 and type(n2) == "string" then name = n2 end
    end
    -- second return of identifyexecutor is often the version
    local ok3, a, b = pcall(function() return identifyexecutor() end)
    if ok3 and type(b) == "string" then ver = b end

    report.executor.name = name
    report.executor.version = ver
    report.executor.luau_version = _VERSION

    local markers = {
        "syn", "krnl", "Krnl", "KRNL_LOADED", "Wave", "WAVE", "Xeno", "XENO_LOADED",
        "Solara", "SOLARA", "Velocity", "VELOCITY_LOADED", "AWP", "Fluxus", "FLUXUS",
        "is_sirhurt_closure", "PROTOSMASHER_LOADED", "SENTINEL_V2", "SCRIPTWARE_ENV",
        "Electron", "OXYGEN_LOADED", "hydrogen", "Delta", "Argon", "Codex",
    }
    local seen = {}
    for _, m in ipairs(markers) do
        if rawget(genv, m) ~= nil then
            seen[m] = typedesc(rawget(genv, m))
        end
    end
    report.executor.globals_seen = seen

    -- Stable fingerprint from sorted top-level keys of getgenv
    local keys = {}
    for k in pairs(genv) do
        if type(k) == "string" then keys[#keys + 1] = k end
    end
    table.sort(keys)
    report.executor.getgenv_key_count = #keys
    report.executor.fingerprint_hash = fnvHash(table.concat(keys, "|"))
end

--==================================================================
-- 2. Roblox VM context
--==================================================================

do
    local function svc(n)
        local ok, s = pcall(game.GetService, game, n)
        if ok then return s end
        return nil
    end
    local Players = svc("Players")
    local RunService = svc("RunService")
    local HttpService = svc("HttpService")

    local function grab(f) local ok, v = pcall(f); if ok then return v end end
    report.roblox.placeId     = grab(function() return game.PlaceId end)
    report.roblox.gameId      = grab(function() return game.GameId end)
    report.roblox.jobId       = grab(function() return game.JobId end)
    report.roblox.creatorId   = grab(function() return game.CreatorId end)
    report.roblox.creatorType = grab(function() return tostring(game.CreatorType) end)

    if RunService then
        local _, c = safe(function() return RunService:IsClient() end); report.roblox.isClient = c
        local _, s = safe(function() return RunService:IsStudio() end); report.roblox.isStudio = s
        local _, r = safe(function() return RunService:IsRunning() end); report.roblox.isRunning = r
    end

    if Players then
        local lp = Players.LocalPlayer
        if lp then
            report.roblox.player = {
                UserId = lp.UserId,
                Name = lp.Name,
                DisplayName = lp.DisplayName,
                AccountAge = lp.AccountAge,
                MembershipType = tostring(lp.MembershipType),
            }
        end
    end

    report.roblox.httpService_reachable = HttpService ~= nil
    if HttpService then
        local ok, v = safe(function() return HttpService.HttpEnabled end)
        report.roblox.httpEnabled = ok and v or "unknown"
    end
end

--==================================================================
-- 3. API surface enumeration
--==================================================================

do
    local genv = (pcall(getgenv) and getgenv()) or _G
    local groups = {
        filesystem = {
            "writefile","readfile","appendfile","loadfile","listfiles",
            "isfile","isfolder","makefolder","delfile","delfolder",
            "getcustomasset","getsynasset",
        },
        network = {
            "request","http_request","http","syn","fluxus",
            "WebSocket","websocket",
        },
        closures = {
            "hookfunction","hookmetamethod","newcclosure","newlclosure",
            "iscclosure","islclosure","checkcaller","clonefunction",
            "getcallingscript","getscriptclosure","getscriptbytecode",
            "getscripthash","getfunctionhash","dumpstring","decompile",
        },
        metatable = {
            "getrawmetatable","setrawmetatable","setreadonly","isreadonly",
            "getnamecallmethod","setnamecallmethod",
        },
        reflection = {
            "getgc","getreg","getgenv","getrenv","getfenv","setfenv",
            "getloadedmodules","getscripts","getinstances","getnilinstances",
        },
        instances = {
            "getconnections","firesignal","fireclickdetector","fireproximityprompt",
            "firetouchinterest","getcallbackvalue","cloneref","compareinstances",
            "gethui","gethiddenproperty","sethiddenproperty",
        },
        direct_escape = {
            "messagebox","os.execute","io.popen","io.open","ffi",
            "package","loadlib","Drawing","require",
            "syn.messagebox","syn.execute",
        },
        clipboard = {
            "setclipboard","toclipboard","Clipboard",
        },
        misc = {
            "identifyexecutor","getexecutorname","queue_on_teleport",
            "syn.queue_on_teleport","saveinstance","gethwid","getreg",
        },
    }

    local function probe(name)
        local root = genv
        local v = root
        for part in string.gmatch(name, "[^%.]+") do
            if type(v) ~= "table" and type(v) ~= "userdata" then
                v = nil; break
            end
            local ok, next_v = pcall(function() return v[part] end)
            if not ok then v = nil; break end
            v = next_v
        end
        if v == nil then return { exists = false } end
        local entry = { exists = true, type = typedesc(v) }
        if entry.type == "lfunction" or entry.type == "cfunction" or entry.type == "function" then
            local ok, src = pcall(debug.info, v, "s")
            if ok and src then entry.source = tostring(src) end
            local ok2, nparams = pcall(debug.info, v, "a")
            if ok2 and nparams then entry.arity = tostring(nparams) end
        end
        return entry
    end

    for gname, list in pairs(groups) do
        local out = {}
        for _, api in ipairs(list) do
            out[api] = probe(api)
        end
        report.api[gname] = out
    end
end

--==================================================================
-- 4. Filesystem attack surface (active probes with canaries)
--==================================================================

do
    local fs = report.fs_probes
    local writefile = rawget(_G, "writefile") or (getgenv and getgenv().writefile)
    local isfile    = rawget(_G, "isfile")    or (getgenv and getgenv().isfile)
    local delfile   = rawget(_G, "delfile")   or (getgenv and getgenv().delfile)
    local listfiles = rawget(_G, "listfiles") or (getgenv and getgenv().listfiles)
    local getcustomasset = rawget(_G, "getcustomasset") or rawget(_G, "getsynasset")
                          or (getgenv and (getgenv().getcustomasset or getgenv().getsynasset))

    fs.writefile_available = type(writefile) == "function"
    fs.isfile_available    = type(isfile)    == "function"
    fs.delfile_available   = type(delfile)   == "function"
    fs.listfiles_available = type(listfiles) == "function"

    fs.left_artifacts = {}
    local function tryCanary(path)
        local out = { path = path }
        if not writefile then out.err = "no writefile"; return out end
        local ok, e = pcall(writefile, path, "canary")
        out.write_ok = ok
        if not ok then out.err = tostring(e); return out end
        if isfile then
            local ok2, r = pcall(isfile, path)
            out.isfile_after = ok2 and r
        end
        if delfile then
            local ok3, e3 = pcall(delfile, path)
            out.delete_ok = ok3
            if not ok3 then out.delete_err = tostring(e3) end
        end
        -- Verify removal. If the file is still there, escalate.
        if isfile then
            local ok4, still = pcall(isfile, path)
            if ok4 then
                out.verified_removed = not still
                if still then
                    table.insert(fs.left_artifacts, path)
                    err("fs", "LEFT_ARTIFACT: " .. path)
                    warn("[Recon] LEFT_ARTIFACT on disk: " .. path)
                end
            else
                out.verified_removed = "isfile err: " .. tostring(still)
            end
        else
            -- No isfile: try a second delete blind
            if delfile then pcall(delfile, path) end
            out.verified_removed = "no_isfile"
        end
        return out
    end

    -- Workspace path leak via getcustomasset
    do
        local name = "recon_" .. randStr() .. ".txt"
        local ok, e = pcall(function() writefile(name, "leak") end)
        if ok and getcustomasset then
            local ok2, uri = pcall(getcustomasset, name)
            fs.workspace_asset_uri = ok2 and tostring(uri) or ("err: " .. tostring(uri))
        elseif not ok then
            fs.workspace_asset_uri = "write failed: " .. tostring(e)
        end
        if delfile then pcall(delfile, name) end
    end

    -- Traversal depth
    do
        fs.traversal = {}
        for depth = 1, 6 do
            local prefix = string.rep("../", depth)
            local path = prefix .. "recon_" .. randStr() .. ".txt"
            fs.traversal["depth_" .. depth] = tryCanary(path)
        end
    end

    -- Absolute paths
    do
        fs.absolute = {}
        local candidates = {
            "C:/Users/Public/recon_" .. randStr() .. ".txt",
            "C:\\Users\\Public\\recon_" .. randStr() .. ".txt",
            "/tmp/recon_" .. randStr() .. ".txt",
        }
        for _, p in ipairs(candidates) do
            fs.absolute[p] = tryCanary(p)
        end
    end

    -- Extension blacklist
    do
        fs.extensions = {}
        local exts = { "txt","lua","luau","json","vbs","bat","cmd","exe","dll","lnk","js","hta","ps1","url","scr","com","msi","jar" }
        for _, ext in ipairs(exts) do
            local path = "recon_" .. randStr() .. "." .. ext
            fs.extensions[ext] = tryCanary(path)
        end
    end

    -- listfiles reach
    do
        fs.listfiles_reach = {}
        local targets = { "", ".", "..", "../..", "../../..", "C:/", "C:/Users", "C:\\", "/" }
        for _, t in ipairs(targets) do
            if listfiles then
                local ok, r = pcall(listfiles, t)
                if ok then
                    local count = 0
                    if type(r) == "table" then count = #r end
                    fs.listfiles_reach[t == "" and "<empty>" or t] = { ok = true, count = count, sample = type(r) == "table" and r[1] or nil }
                else
                    fs.listfiles_reach[t == "" and "<empty>" or t] = { ok = false, err = tostring(r) }
                end
            end
        end
    end

    -- Startup folder reachability. Uses .recon_probe extension so Windows
    -- won't auto-execute even if delete verification fails. tryCanary above
    -- will warn to console and record in fs.left_artifacts on any leftover.
    do
        local candidates = {
            [[../../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/recon_]] .. randStr() .. ".recon_probe",
            [[../../../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/recon_]] .. randStr() .. ".recon_probe",
            [[../../../../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/recon_]] .. randStr() .. ".recon_probe",
            [[C:/Users/Public/recon_startup_]] .. randStr() .. ".recon_probe",
        }
        fs.startup_reach = {}
        for _, p in ipairs(candidates) do
            fs.startup_reach[p] = tryCanary(p)
        end
    end
end

--==================================================================
-- 4b. Shell escape: os.execute / io.popen roundtrip
--==================================================================

do
    local sh = report.shell
    local writefile = rawget(_G, "writefile") or (getgenv and getgenv().writefile)
    local readfile  = rawget(_G, "readfile")  or (getgenv and getgenv().readfile)
    local isfile    = rawget(_G, "isfile")    or (getgenv and getgenv().isfile)
    local delfile   = rawget(_G, "delfile")   or (getgenv and getgenv().delfile)

    sh.os_execute_present = type(os) == "table" and type(os.execute) == "function"
    sh.io_popen_present   = type(io) == "table" and type(io.popen)   == "function"
    sh.io_open_present    = type(io) == "table" and type(io.open)    == "function"

    -- os.execute: redirect echo into workspace-relative file, then read via
    -- executor's readfile. Positive result = real shell reaches disk.
    if sh.os_execute_present then
        local nonce = "recon_" .. randStr()
        local probeFile = nonce .. ".osx.txt"
        -- On Windows shells, "echo" writes with a trailing CRLF
        local cmd = 'echo ' .. nonce .. ' > "' .. probeFile .. '"'
        local ok, rc = pcall(os.execute, cmd)
        sh.os_execute_call_ok = ok
        sh.os_execute_return  = ok and tostring(rc) or tostring(rc)
        if ok and isfile then
            local ok2, present = pcall(isfile, probeFile)
            sh.os_execute_produced_file = ok2 and present
            if ok2 and present and readfile then
                local ok3, contents = pcall(readfile, probeFile)
                if ok3 and type(contents) == "string" and contents:find(nonce, 1, true) then
                    sh.os_execute_roundtrip = true
                else
                    sh.os_execute_roundtrip = false
                    sh.os_execute_readback = ok3 and #contents or tostring(contents)
                end
            end
            if delfile then pcall(delfile, probeFile) end
        end
    end

    -- io.popen: read stdout directly
    if sh.io_popen_present then
        local nonce = "recon_" .. randStr()
        local ok, handle = pcall(io.popen, "echo " .. nonce)
        sh.io_popen_call_ok = ok
        if ok and handle then
            local ok2, output = pcall(function() return handle:read("*a") end)
            pcall(function() handle:close() end)
            if ok2 and type(output) == "string" and output:find(nonce, 1, true) then
                sh.io_popen_roundtrip = true
                sh.io_popen_sample = output:sub(1, 120)
            else
                sh.io_popen_roundtrip = false
                sh.io_popen_output_type = safeType(output)
            end
        end
    end

    -- io.open: does the userland C stdio API reach the real disk?
    if sh.io_open_present then
        local nonce = "recon_" .. randStr()
        local probeFile = "recon_" .. nonce .. ".ioopen.txt"
        local ok, fh = pcall(io.open, probeFile, "w")
        sh.io_open_write_ok = ok and fh ~= nil
        if ok and fh then
            pcall(function() fh:write(nonce); fh:close() end)
            if isfile then
                local ok2, present = pcall(isfile, probeFile)
                sh.io_open_produced_file = ok2 and present
            end
            local ok3, fh2 = pcall(io.open, probeFile, "r")
            if ok3 and fh2 then
                local ok4, contents = pcall(function() return fh2:read("*a") end)
                pcall(function() fh2:close() end)
                sh.io_open_roundtrip = ok4 and type(contents) == "string" and contents:find(nonce, 1, true) ~= nil
            end
            if delfile then pcall(delfile, probeFile) end
        end
    end
end

--==================================================================
-- 4c. Persistence primitives
--==================================================================

do
    local pers = report.persistence
    local genv = (pcall(getgenv) and getgenv()) or _G

    local candidates = {
        "queue_on_teleport",
        "syn.queue_on_teleport",
        "queueonteleport",
        "run_on_actor",
        "runonactor",
        "getactors",
        "get_thread_identity",
        "getthreadidentity",
        "setthreadidentity",
        "setidentity",
        "printidentity",
    }
    for _, name in ipairs(candidates) do
        local v = genv
        for part in string.gmatch(name, "[^%.]+") do
            if type(v) ~= "table" then v = nil; break end
            v = rawget(v, part)
        end
        if v ~= nil then
            local entry = { type = typedesc(v) }
            if entry.type == "cfunction" or entry.type == "lfunction" then
                local ok, arity = pcall(debug.info, v, "a")
                if ok then entry.arity = tostring(arity) end
                local ok2, src = pcall(debug.info, v, "s")
                if ok2 then entry.source = tostring(src) end
            end
            pers[name] = entry
        end
    end

    -- Read current identity without changing it
    local printid = rawget(genv, "printidentity")
    if type(printid) == "function" then
        pers.printidentity_callable = true
    end
    local getid = rawget(genv, "getthreadidentity") or rawget(genv, "get_thread_identity")
    if type(getid) == "function" then
        local ok, v = pcall(getid)
        if ok then pers.current_thread_identity = tostring(v) end
    end
end

--==================================================================
-- 4d. Clipboard roundtrip
--==================================================================

do
    local cb = report.clipboard
    local genv = (pcall(getgenv) and getgenv()) or _G
    local writers = { "setclipboard", "toclipboard" }
    local readers = { "getclipboard", "readclipboard" }

    for _, n in ipairs(writers) do
        if type(rawget(genv, n)) == "function" then cb["writer_" .. n] = true end
    end
    for _, n in ipairs(readers) do
        if type(rawget(genv, n)) == "function" then cb["reader_" .. n] = true end
    end

    local write = rawget(genv, "setclipboard") or rawget(genv, "toclipboard")
    local read  = rawget(genv, "getclipboard") or rawget(genv, "readclipboard")
    if type(write) == "function" then
        local nonce = "RECON_CB_" .. randStr()
        -- Save prior clipboard if we can read it
        local prior
        if type(read) == "function" then
            local ok, r = pcall(read)
            if ok then prior = r end
        end
        local ok = pcall(write, nonce)
        cb.write_call_ok = ok
        if type(read) == "function" then
            local ok2, back = pcall(read)
            cb.read_call_ok = ok2
            if ok2 and back == nonce then
                cb.roundtrip = true
            else
                cb.roundtrip = false
                cb.readback_sample_len = ok2 and (type(back) == "string" and #back or safeType(back))
            end
            -- Restore prior clipboard best-effort
            if prior ~= nil then pcall(write, prior) end
        else
            cb.roundtrip = "no_reader"
        end
    end
end

--==================================================================
-- 5. Closure / memory poking
--==================================================================

do
    local mem = report.memory

    -- debug.info source leaks
    local ok1, src1 = pcall(debug.info, print, "s")
    mem.debug_info_print_source = ok1 and tostring(src1) or nil
    local ok2, src2 = pcall(debug.info, warn, "s")
    mem.debug_info_warn_source = ok2 and tostring(src2) or nil

    -- getgc counts
    if type(getgc) == "function" then
        local ok, all = pcall(getgc, true)
        if ok and type(all) == "table" then
            local c = { total = #all, ["function"] = 0, table = 0, userdata = 0, thread = 0, other = 0 }
            for i = 1, math.min(#all, 20000) do
                local tt = safeType(all[i])
                if c[tt] ~= nil then c[tt] = c[tt] + 1 else c.other = c.other + 1 end
            end
            mem.gc_counts = c
        else
            mem.gc_counts = "err: " .. tostring(all)
        end
    end

    -- getrawmetatable on game
    if type(getrawmetatable) == "function" then
        local ok, mt = pcall(getrawmetatable, game)
        mem.game_metatable_accessible = ok and mt ~= nil
        if ok and type(mt) == "table" then
            mem.game_metatable_index_type = safeType(rawget(mt, "__index"))
        end
    end

    -- setreadonly on throwaway
    if type(setreadonly) == "function" then
        local t = { canary = true }
        local ok1r = pcall(setreadonly, t, true)
        local ok2r = pcall(setreadonly, t, false)
        mem.setreadonly_works_on_local_table = ok1r and ok2r
    end

    -- hookfunction on local lclosure
    if type(hookfunction) == "function" then
        local target = function() return "orig" end
        local replacement = function() return "hooked" end
        local ok, orig = pcall(hookfunction, target, replacement)
        if ok then
            local ok2, r = pcall(target)
            mem.hookfunction_local_lclosure = ok2 and r == "hooked"
            if type(orig) == "function" then pcall(hookfunction, target, orig) end
        else
            mem.hookfunction_local_lclosure = false
            mem.hookfunction_err = tostring(orig)
        end
        -- Attempt on a C closure that's cheap and reversible: math.abs
        if type(newcclosure) == "function" then
            local safe_replacement = newcclosure(function(x) return x end)
            local ok3, orig2 = pcall(hookfunction, math.abs, safe_replacement)
            if ok3 then
                local ok4, r2 = pcall(math.abs, -5)
                mem.hookfunction_cclosure = ok4 and r2 == -5
                if type(orig2) == "function" then pcall(hookfunction, math.abs, orig2) end
            else
                mem.hookfunction_cclosure = false
            end
        end
    end

    -- string.dump on local closure
    do
        local f = function() return 42 end
        local ok, bc = pcall(string.dump, f)
        mem.string_dump_local = ok and type(bc) == "string" and #bc > 0
    end

    -- getreg size
    if type(getreg) == "function" then
        local ok, r = pcall(getreg)
        if ok and type(r) == "table" then
            local n = 0
            for _ in pairs(r) do n = n + 1 end
            mem.getreg_size = n
        end
    end

    -- cloneref
    if type(cloneref) == "function" then
        local ok, cg = pcall(cloneref, game:GetService("CoreGui"))
        mem.cloneref_works = ok and cg ~= nil
    end

    -- checkcaller
    if type(checkcaller) == "function" then
        local ok, r = pcall(checkcaller)
        mem.checkcaller_returns = ok and tostring(r) or "err"
    end

    -- getrenv vs getgenv
    if type(getrenv) == "function" and type(getgenv) == "function" then
        local a, b = pcall(getrenv), pcall(getgenv)
        if a and b then mem.genv_is_renv = getgenv() == getrenv() end
    end
end

--==================================================================
-- 6. Interesting GC objects
--==================================================================

do
    local gs = report.gc_scan
    if type(getgc) ~= "function" then gs.available = false else
        gs.available = true
        local ok, all = pcall(getgc, true)
        if not ok or type(all) ~= "table" then gs.err = tostring(all) else
            gs.total = #all
            local funcSamples, sensitiveHits, cclosures = {}, {}, {}
            local sensitiveKeys = {
                Token = true, token = true, Key = true, key = true,
                Secret = true, secret = true, Session = true, session = true,
                Cookie = true, cookie = true, Auth = true, auth = true,
                Password = true, password = true, ApiKey = true, apikey = true,
            }
            local isC = type(iscclosure) == "function" and iscclosure or nil
            local funcCount, tableCount, sensCount, cCount = 0, 0, 0, 0
            local CCLOSURE_LIMIT = 60
            local seenName = {}
            for i = 1, math.min(#all, 15000) do
                local v = all[i]
                local tt = safeType(v)
                if tt == "function" then
                    if funcCount < 8 then
                        local ok2, src = pcall(debug.info, v, "s")
                        funcSamples[#funcSamples + 1] = { src = ok2 and tostring(src) or "?" }
                        funcCount = funcCount + 1
                    end
                    -- C closure enumeration for Phase 2 pivot candidates
                    if isC and cCount < CCLOSURE_LIMIT then
                        local okC, isCC = pcall(isC, v)
                        if okC and isCC then
                            local okN, name = pcall(debug.info, v, "n")
                            local okS, src  = pcall(debug.info, v, "s")
                            local key = (okN and tostring(name) or "?") .. "@" .. (okS and tostring(src) or "?")
                            if not seenName[key] then
                                seenName[key] = true
                                cclosures[#cclosures + 1] = {
                                    name = okN and tostring(name) or nil,
                                    source = okS and tostring(src) or nil,
                                    addr = tostring(v),
                                }
                                cCount = cCount + 1
                            end
                        end
                    end
                elseif tt == "table" and tableCount < 3000 then
                    tableCount = tableCount + 1
                    if sensCount < 10 then
                        pcall(function()
                            for k in pairs(v) do
                                if sensitiveKeys[k] then
                                    sensCount = sensCount + 1
                                    sensitiveHits[#sensitiveHits + 1] = {
                                        key = tostring(k),
                                        value_type = safeType(v[k]),
                                        table_size_hint = "sampled",
                                    }
                                    break
                                end
                            end
                        end)
                    end
                end
            end
            gs.sample_functions = funcSamples
            gs.sensitive_key_hits = sensitiveHits
            gs.tables_scanned = tableCount
            gs.cclosures = cclosures
            gs.cclosures_count_sampled = cCount
        end
    end

    -- Sample debug.getconstants / getupvalues on a local closure
    do
        local marker = "recon_upvalue_" .. randStr()
        local sample = function() return marker end
        local out = {}
        if debug.getconstants then
            local ok, c = pcall(debug.getconstants, sample)
            out.constants = ok and c or ("err: " .. tostring(c))
        end
        if debug.getupvalues then
            local ok, u = pcall(debug.getupvalues, sample)
            out.upvalues = ok and u or ("err: " .. tostring(u))
        end
        if debug.getprotos then
            local ok, p = pcall(debug.getprotos, sample)
            out.protos_count = ok and (type(p) == "table" and #p) or "err"
        end
        gs.local_closure_introspection = out
    end
end

--==================================================================
-- 7. Native / host-boundary signals
--==================================================================

do
    local n = report.native

    -- Drawing library
    if type(Drawing) == "table" and type(Drawing.new) == "function" then
        local ok, obj = pcall(Drawing.new, "Square")
        n.drawing_available = ok
        if ok then
            n.drawing_object_string = tostring(obj)
            pcall(function() obj:Remove() end)
        end
    else
        n.drawing_available = false
    end

    -- newcclosure address pattern
    if type(newcclosure) == "function" then
        local addrs = {}
        for i = 1, 3 do
            local ok, c = pcall(newcclosure, function() end)
            if ok then addrs[i] = tostring(c) end
        end
        n.newcclosure_addresses = addrs
    end

    -- ffi presence (LuaJIT-style FFI). If load works we are one line away
    -- from calling user32!MessageBoxA. We do NOT invoke it here.
    do
        local ffi = rawget(_G, "ffi")
        if ffi == nil and type(getgenv) == "function" then
            local ok, g = pcall(getgenv); if ok then ffi = rawget(g, "ffi") end
        end
        if type(ffi) == "table" then
            local out = { present = true }
            out.has_load  = type(rawget(ffi, "load"))  == "function"
            out.has_cdef  = type(rawget(ffi, "cdef"))  == "function"
            out.has_C     = rawget(ffi, "C") ~= nil
            out.has_new   = type(rawget(ffi, "new"))   == "function"
            out.has_cast  = type(rawget(ffi, "cast"))  == "function"
            out.os        = tostring(rawget(ffi, "os"))
            out.arch      = tostring(rawget(ffi, "arch"))
            if out.has_load then
                local ok, u32 = pcall(ffi.load, "user32")
                out.load_user32_ok = ok
                out.load_user32_type = ok and safeType(u32) or nil
                out.load_user32_str  = ok and tostring(u32):sub(1, 120) or tostring(u32):sub(1, 200)
            end
            n.ffi = out
        else
            n.ffi = { present = false }
        end
    end

    -- LuaJIT bit library (native, sometimes present alongside bit32)
    do
        local bit = rawget(_G, "bit")
        n.bit_library_present = type(bit) == "table" and type(rawget(bit, "band")) == "function"
    end

    -- Executor-specific direct escapes (presence + arity only, no call)
    do
        local genv = (pcall(getgenv) and getgenv()) or _G
        local direct = {
            "messagebox", "MessageBox",
            "syn.messagebox", "syn.execute",
            "krnl.messagebox",
        }
        local hits = {}
        for _, name in ipairs(direct) do
            local v = genv
            for part in string.gmatch(name, "[^%.]+") do
                if type(v) ~= "table" then v = nil; break end
                v = rawget(v, part)
            end
            if v ~= nil then
                local entry = { type = typedesc(v) }
                if entry.type == "cfunction" or entry.type == "lfunction" then
                    local ok, a = pcall(debug.info, v, "a"); if ok then entry.arity = tostring(a) end
                end
                hits[name] = entry
            end
        end
        n.direct_native_hits = hits
    end

    -- Clock drift
    do
        local samples = {}
        local ok1, a = pcall(function() return os.clock() end); samples.os_clock = ok1 and a
        local ok2, b = pcall(function() return tick() end); samples.tick = ok2 and b
        local ok3, c = pcall(function() return DateTime.now().UnixTimestampMillis end); samples.datetime_ms = ok3 and c
        local ok4, d = pcall(function() return workspace:GetServerTimeNow() end); samples.server_time = ok4 and d
        n.clocks = samples
    end
end

--==================================================================
-- 7b. Native-call gadget detection (Tier B)
--
-- The question this section answers: can a script assemble a call to
-- user32!MessageBoxA from what the executor exposes? A full native call
-- needs (at minimum) three of: a way to resolve a module base, a way to
-- resolve an export address, and a way to transfer control to it. We probe
-- each capability class, and for the SAFE ones we actually resolve
-- MessageBoxA's address to prove the leg works -- without ever calling it.
--==================================================================

do
    local nc = report.native_call

    -- 1) Raw memory read/write primitives (name-only + shape probe)
    local memReadNames = {
        "readmemory", "read_memory", "readbytes", "read_bytes",
        "readu8","readu16","readu32","readu64","readi8","readi16","readi32","readi64",
        "readqword","readdword","readword","readbyte","readfloat","readdouble",
        "readstring", "read_string", "readpointer", "read_pointer",
    }
    local memWriteNames = {
        "writememory","write_memory","writebytes","write_bytes",
        "writeu8","writeu16","writeu32","writeu64","writei8","writei16","writei32","writei64",
        "writeqword","writedword","writeword","writebyte","writefloat","writedouble",
        "writestring","write_string","writepointer","write_pointer",
    }
    nc.mem_read = {}
    for _, name in ipairs(memReadNames) do
        local v = resolveGlobal(name)
        if v ~= nil then nc.mem_read[name] = fnMeta(v) end
    end
    nc.mem_write = {}
    for _, name in ipairs(memWriteNames) do
        local v = resolveGlobal(name)
        if v ~= nil then nc.mem_write[name] = fnMeta(v) end
    end
    nc.has_mem_read  = next(nc.mem_read)  ~= nil
    nc.has_mem_write = next(nc.mem_write) ~= nil

    -- 2) Module-base resolution. SAFE to call: read-only lookups.
    do
        local getbase, gbName = firstGlobal({
            "getmodulebase","get_module_base","getmodulehandle","get_module_handle",
            "getbaseaddress","get_base_address","getmodulebaseaddress","getmodule",
        })
        nc.module_base = { primitive = gbName }
        if type(getbase) == "function" then
            for _, mod in ipairs({ "user32.dll", "user32", "kernel32.dll", "kernel32",
                                   "RobloxPlayerBeta.exe", "" }) do
                local ok, base = pcall(getbase, mod)
                if ok and base ~= nil then
                    nc.module_base[mod == "" and "<self>" or mod] = tostring(base)
                end
            end
        end
    end

    -- 3) Export resolution. SAFE to call: GetProcAddress is read-only.
    do
        local getproc, gpName = firstGlobal({
            "getprocaddress","get_proc_address","getexportaddress","get_export_address",
            "getprocedureaddress","getfunctionaddress_native","dlsym",
        })
        nc.export_resolve = { primitive = gpName }
        if type(getproc) == "function" then
            -- Try a couple of calling conventions: (module, symbol) and (symbol)
            local attempts = {
                function() return getproc("user32.dll", "MessageBoxA") end,
                function() return getproc("user32", "MessageBoxA") end,
                function() return getproc("MessageBoxA") end,
                function() return getproc("user32.dll", "MessageBoxW") end,
            }
            for i, fn in ipairs(attempts) do
                local ok, addr = pcall(fn)
                if ok and addr ~= nil then
                    nc.export_resolve["attempt_" .. i] = tostring(addr)
                    nc.export_resolve.messagebox_resolved = true
                end
            end
        end
    end

    -- 4) Allocation + protection primitives (name-only; calling these has
    --    side effects / risk of leaking committed pages, so we don't invoke).
    nc.alloc = {}
    for _, name in ipairs({
        "virtualalloc","virtual_alloc","allocatememory","allocate_memory",
        "malloc","alloc","virtualallocex","createheap",
    }) do
        local v = resolveGlobal(name); if v ~= nil then nc.alloc[name] = fnMeta(v) end
    end
    nc.protect = {}
    for _, name in ipairs({
        "virtualprotect","virtual_protect","setpageprotection","set_page_protection",
        "protectmemory","mprotect",
    }) do
        local v = resolveGlobal(name); if v ~= nil then nc.protect[name] = fnMeta(v) end
    end

    -- 5) Control-transfer gadgets: the actual "call this address" primitive.
    nc.call_gadget = {}
    for _, name in ipairs({
        "callfunction","call_function","nativecall","native_call","calldll","call_dll",
        "callcfunction","syscall","createnativeclosure","create_native_closure",
        "getnativeclosure","newnativeclosure","runcode","run_code","executecode",
        "shellcode","execute_shellcode","spawnnativethread","createthread","create_thread",
    }) do
        local v = resolveGlobal(name); if v ~= nil then nc.call_gadget[name] = fnMeta(v) end
    end
    nc.has_call_gadget = next(nc.call_gadget) ~= nil

    -- 6) lua_State / mainthread leaks (needed for most manual-map call chains)
    do
        local st, stName = firstGlobal({
            "getluastate","get_lua_state","getstate","getmainthread","get_main_thread",
            "getrobloxstate","getthreadstate",
        })
        nc.lua_state = { primitive = stName }
        if type(st) == "function" then
            local ok, s

do
    local e = report.env
    if type(os) == "table" then
        e.os_keys = {}
        for k, v in pairs(os) do
            e.os_keys[k] = safeType(v)
        end
        if type(os.getenv) == "function" then
            local vars = { "USERNAME", "USER", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "COMPUTERNAME", "HOME", "PATH" }
            e.os_getenv = {}
            for _, v in ipairs(vars) do
                local ok, val = pcall(os.getenv, v)
                if ok and val ~= nil then e.os_getenv[v] = tostring(val) end
            end
        end
    end
    if type(io) == "table" then
        e.io_keys = {}
        for k, v in pairs(io) do e.io_keys[k] = safeType(v) end
    end
    if type(package) == "table" then
        e.package_keys = {}
        for k, v in pairs(package) do e.package_keys[k] = safeType(v) end
    end
    -- Suspicious hints in _G
    local hints = {}
    for k, v in pairs(_G) do
        if type(k) == "string" then
            local kl = k:lower()
            if kl:find("windows") or kl:find("appdata") or kl:find("user") or kl:find("path") then
                hints[k] = safeType(v)
            end
        end
    end
    e.suspicious_globals = hints
end

--==================================================================
-- Serialize
--==================================================================

local serialized = serialize(report)

--==================================================================
-- Console output
--==================================================================

do
    print("========================================")
    print(" Roblox Executor Recon v" .. SCANNER_VERSION)
    print("========================================")
    print(" Executor : " .. tostring(report.executor.name) .. " " .. tostring(report.executor.version))
    print(" LuaU     : " .. tostring(report.executor.luau_version))
    print(" Fpr Hash : " .. tostring(report.executor.fingerprint_hash))
    print(" Place    : " .. tostring(report.roblox.placeId) .. " (JobId " .. tostring(report.roblox.jobId) .. ")")
    print(" Studio?  : " .. tostring(report.roblox.isStudio))
    print("----- FULL REPORT (also in GUI) -----")
    -- Executors' consoles vary in max line length; chunk to be safe
    local step = 900
    for i = 1, #serialized, step do
        print(serialized:sub(i, i + step - 1))
    end
    print("----- END REPORT -----")
end

--==================================================================
-- GUI
--==================================================================

do
    local ok, guiErr = pcall(function()
        local parentGui
        local ok_hui, hui = pcall(function() return gethui() end)
        if ok_hui and hui then
            parentGui = hui
        else
            local cg
            local ok_cg, cgv = pcall(function() return game:GetService("CoreGui") end)
            if ok_cg and cgv then cg = cgv end
            if cg and type(cloneref) == "function" then
                local ok_c, cref = pcall(cloneref, cg)
                if ok_c then cg = cref end
            end
            parentGui = cg
        end
        if not parentGui then
            local Players = game:GetService("Players")
            parentGui = Players.LocalPlayer:WaitForChild("PlayerGui")
        end

        -- Clean prior instance
        local prior = parentGui:FindFirstChild("ReconScannerGui")
        if prior then prior:Destroy() end

        local ScreenGui = Instance.new("ScreenGui")
        ScreenGui.Name = "ReconScannerGui"
        ScreenGui.ResetOnSpawn = false
        ScreenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
        ScreenGui.IgnoreGuiInset = true
        ScreenGui.Parent = parentGui

        local Main = Instance.new("Frame")
        Main.Size = UDim2.new(0, 700, 0, 500)
        Main.Position = UDim2.new(0.5, -350, 0.5, -250)
        Main.BackgroundColor3 = Color3.fromRGB(15, 15, 20)
        Main.BorderSizePixel = 0
        Main.Active = true
        Main.Draggable = true
        Main.Parent = ScreenGui

        local corner = Instance.new("UICorner")
        corner.CornerRadius = UDim.new(0, 10)
        corner.Parent = Main

        local stroke = Instance.new("UIStroke")
        stroke.Color = Color3.fromRGB(40, 42, 50)
        stroke.Thickness = 1.5
        stroke.Parent = Main

        local Title = Instance.new("TextLabel")
        Title.Size = UDim2.new(1, 0, 0, 40)
        Title.BackgroundColor3 = Color3.fromRGB(22, 24, 30)
        Title.BorderSizePixel = 0
        Title.Text = "  Roblox Executor Recon   v" .. SCANNER_VERSION .. "   [" .. tostring(report.executor.name) .. "]"
        Title.TextColor3 = Color3.fromRGB(240, 240, 240)
        Title.Font = Enum.Font.GothamBold
        Title.TextSize = 14
        Title.TextXAlignment = Enum.TextXAlignment.Left
        Title.Parent = Main

        local tCorner = Instance.new("UICorner")
        tCorner.CornerRadius = UDim.new(0, 10)
        tCorner.Parent = Title
        
        -- Fix bottom corners of title to connect seamlessly
        local tFix = Instance.new("Frame")
        tFix.Size = UDim2.new(1, 0, 0, 10)
        tFix.Position = UDim2.new(0, 0, 1, -10)
        tFix.BackgroundColor3 = Color3.fromRGB(22, 24, 30)
        tFix.BorderSizePixel = 0
        tFix.Parent = Title

        local TitleStroke = Instance.new("UIStroke")
        TitleStroke.Color = Color3.fromRGB(40, 42, 50)
        TitleStroke.Thickness = 1
        TitleStroke.Parent = Title

        local Scroll = Instance.new("ScrollingFrame")
        Scroll.Size = UDim2.new(1, -30, 1, -110)
        Scroll.Position = UDim2.new(0, 15, 0, 55)
        Scroll.BackgroundColor3 = Color3.fromRGB(10, 10, 14)
        Scroll.BorderSizePixel = 0
        Scroll.ScrollBarThickness = 4
        Scroll.ScrollBarImageColor3 = Color3.fromRGB(80, 85, 100)
        Scroll.CanvasSize = UDim2.new(0, 0, 0, 0)
        Scroll.AutomaticCanvasSize = Enum.AutomaticSize.Y
        Scroll.Parent = Main

        local sCorner = Instance.new("UICorner")
        sCorner.CornerRadius = UDim.new(0, 6)
        sCorner.Parent = Scroll
        
        local sStroke = Instance.new("UIStroke")
        sStroke.Color = Color3.fromRGB(30, 32, 40)
        sStroke.Thickness = 1
        sStroke.Parent = Scroll

        local Body = Instance.new("TextBox")
        Body.Size = UDim2.new(1, -16, 0, 0)
        Body.Position = UDim2.new(0, 8, 0, 8)
        Body.AutomaticSize = Enum.AutomaticSize.Y
        Body.BackgroundTransparency = 1
        Body.ClearTextOnFocus = false
        Body.MultiLine = true
        Body.TextEditable = false
        Body.TextWrapped = true
        Body.TextXAlignment = Enum.TextXAlignment.Left
        Body.TextYAlignment = Enum.TextYAlignment.Top
        Body.Font = Enum.Font.Code
        Body.TextSize = 13
        Body.TextColor3 = Color3.fromRGB(180, 190, 210)
        Body.Text = serialized
        Body.Parent = Scroll

        local CopyBtn = Instance.new("TextButton")
        CopyBtn.Size = UDim2.new(0, 200, 0, 36)
        CopyBtn.Position = UDim2.new(0, 15, 1, -45)
        CopyBtn.BackgroundColor3 = Color3.fromRGB(45, 90, 200)
        CopyBtn.BorderSizePixel = 0
        CopyBtn.Text = "Copy to Clipboard"
        CopyBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
        CopyBtn.Font = Enum.Font.GothamSemibold
        CopyBtn.TextSize = 14
        CopyBtn.AutoButtonColor = false
        CopyBtn.Parent = Main
        
        local cbCorner = Instance.new("UICorner")
        cbCorner.CornerRadius = UDim.new(0, 6)
        cbCorner.Parent = CopyBtn

        local CloseBtn = Instance.new("TextButton")
        CloseBtn.Size = UDim2.new(0, 100, 0, 36)
        CloseBtn.Position = UDim2.new(1, -115, 1, -45)
        CloseBtn.BackgroundColor3 = Color3.fromRGB(200, 50, 60)
        CloseBtn.BorderSizePixel = 0
        CloseBtn.Text = "Close"
        CloseBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
        CloseBtn.Font = Enum.Font.GothamSemibold
        CloseBtn.TextSize = 14
        CloseBtn.AutoButtonColor = false
        CloseBtn.Parent = Main
        
        local xCorner = Instance.new("UICorner")
        xCorner.CornerRadius = UDim.new(0, 6)
        xCorner.Parent = CloseBtn

        -- Button hover animations
        local TweenService = game:GetService("TweenService")
        local tInfo = TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.Out)
        
        CopyBtn.MouseEnter:Connect(function()
            TweenService:Create(CopyBtn, tInfo, {BackgroundColor3 = Color3.fromRGB(60, 110, 230)}):Play()
        end)
        CopyBtn.MouseLeave:Connect(function()
            TweenService:Create(CopyBtn, tInfo, {BackgroundColor3 = Color3.fromRGB(45, 90, 200)}):Play()
        end)
        
        CloseBtn.MouseEnter:Connect(function()
            TweenService:Create(CloseBtn, tInfo, {BackgroundColor3 = Color3.fromRGB(230, 60, 70)}):Play()
        end)
        CloseBtn.MouseLeave:Connect(function()
            TweenService:Create(CloseBtn, tInfo, {BackgroundColor3 = Color3.fromRGB(200, 50, 60)}):Play()
        end)

        CloseBtn.MouseButton1Click:Connect(function()
            TweenService:Create(Main, tInfo, {Size = UDim2.new(0, 700, 0, 0), Position = UDim2.new(0.5, -350, 0.5, 0), BackgroundTransparency = 1}):Play()
            task.wait(0.2)
            ScreenGui:Destroy()
        end)

        CopyBtn.MouseButton1Click:Connect(function()
            local copiers = {
                function() return setclipboard(serialized) end,
                function() return toclipboard(serialized) end,
                function() return Clipboard.set(serialized) end,
                function() return Clipboard.Set(serialized) end,
                function() return syn.write_clipboard(serialized) end,
            }
            local success = false
            for _, fn in ipairs(copiers) do
                local ok = pcall(fn)
                if ok then success = true; break end
            end
            local original = CopyBtn.Text
            CopyBtn.Text = success and "Copied!" or "Copy failed"
            if success then
                TweenService:Create(CopyBtn, tInfo, {BackgroundColor3 = Color3.fromRGB(40, 160, 80)}):Play()
            else
                TweenService:Create(CopyBtn, tInfo, {BackgroundColor3 = Color3.fromRGB(160, 160, 160)}):Play()
            end
            task.delay(1.5, function()
                if CopyBtn and CopyBtn.Parent then 
                    CopyBtn.Text = original 
                    TweenService:Create(CopyBtn, tInfo, {BackgroundColor3 = Color3.fromRGB(45, 90, 200)}):Play()
                end
            end)
        end)
        
        -- Startup Animation
        Main.Size = UDim2.new(0, 700, 0, 0)
        Main.Position = UDim2.new(0.5, -350, 0.5, 0)
        TweenService:Create(Main, TweenInfo.new(0.4, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
            Size = UDim2.new(0, 700, 0, 500),
            Position = UDim2.new(0.5, -350, 0.5, -250)
        }):Play()

    end)
    if not ok then
        err("gui", guiErr)
        warn("[Recon] GUI failed: " .. tostring(guiErr) .. " -- report is still in console output above.")
    end
end

return report
