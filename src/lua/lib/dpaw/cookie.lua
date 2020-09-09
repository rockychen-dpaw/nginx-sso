
local utils = require "dpaw.utils"

local _M = {}

--set response cookie
local function _set_response_cookie(cookie_str)
    ngx.header["Set-Cookie"] = cookie_str
end

--Add new cookie
local function _add_response_cookie(cookie_str)
    local existing_cookies = ngx.header["Set-Cookie"]
    if existing_cookies then
        local existing_cookies_type = type(existing_cookies)    
        if existing_cookies_type == "string" then
            local cookies_table = {}
            cookies_table[1] = existing_cookies
            cookies_table[2] = cookie_str
            ngx.header["Set-Cookie"] = cookies_table
        elseif existing_cookies_type == "table" then
            local cookies_table = {}
            local size = #existing_cookies
            for i=1,size do
                cookies_table[i] = existing_cookies[i]
                if cookies_table[i] == cookie_str then
                    -- cookies already exist
                    return
                end
            end
            cookies_table[size + 1] = cookie_str
            ngx.header["Set-Cookie"] = cookies_table
        else
            ngx.header["Set-Cookie"] = cookie_str
        end
    else
        ngx.header["Set-Cookie"] = cookie_str
    end
end

--get all cookies; if not found, return empty array
local function _get_all_response_cookies()
    local existing_cookies = ngx.header["Set-Cookie"]
    if existing_cookies then
        local existing_cookies_type = type(existing_cookies)    
        if existing_cookies_type == "string" then
            return {existing_cookies}
        elseif existing_cookies_type == "table" then
            return existing_cookies
        else
            return {}
        end
    else
        return {}
    end
end

--parse a cookie str to name,value, and properties
local function _parse(cookie_str)
    if cookie_str == nil or string.len(cookie_str) == 0 then
        return nil,nil,nil,"cookie is null."
    else
        local components = utils.split(cookie_str,";")
        local k,v,pos = nil,nil,nil
        local name,value,properties = nil,nil,{}
        for i,component in ipairs(components) do
            pos = string.find(component,"=")
            if pos then
                k = string.sub(component,1,pos - 1)
                v = string.sub(component,pos + 1)
            else
                k = component
                v = "__nil__"
            end
            if i == 1 then
                --name vlaue
                name = k
                value = v
            else
                --properties
                properties[k] = v
            end
        end
        return name,value,properties
    end
end
--clear a cookie
local function _clear_cookie(name,path,domain)
    local cleared_cookie_str = name .. "=deleted"
    if domain then
        cleared_cookie_str = cleared_cookie_str .. ";domain=" .. domain
    end
    if path then
        cleared_cookie_str = cleared_cookie_str .. ";path=" .. path
    else
        cleared_cookie_str = cleared_cookie_str .. ";path=/"
    end
    cleared_cookie_str = cleared_cookie_str .. ";Expires=Thu, 01-Jan-1970 00:00:01 GMT"
    ngx.log(ngx.ERR,"clear cookie: " .. cleared_cookie_str)
    return cleared_cookie_str
end

--clear all cookies;
--cookies are saved in browser side, so removing it from headers can't really remove it. so the effective way is replace the cookie value with deleted and set the expire date
local function _clear_all_cookies(session_cookie,path,domain)
    local request_cookies_str = ngx.req.get_headers()["Cookie"]
    if request_cookies_str and string.len(request_cookies_str) > 0 then
        local response_cookies = {}
        local pos,index = 0,0
        local cookie_name = nil
        for i,cookie_str in pairs(utils.split(request_cookies_str,";")) do
            cookie_str = utils.trim(cookie_str)
            if string.len(cookie_str) > 0 then
                pos = string.find(cookie_str,"=")
                index = index + 1
                if pos then
                    cookie_name = string.sub(cookie_str,1,pos - 1)
                else
                    cookie_name = cookie_str
                end
                if cookie_name == session_cookie then
                    response_cookies[index] = _clear_cookie(cookie_name,"/")
                else
                    response_cookies[index] = _clear_cookie(cookie_name,path,domain)
                end
            end
        end

        local existing_cookies = ngx.header["Set-Cookie"]
        if existing_cookies then
            local existing_cookies_type = type(existing_cookies)    
            if existing_cookies_type == "string" then
                index = index + 1
                response_cookies[index] = existing_cookies
            elseif existing_cookies_type == "table" then
                for i,cookie_str in pairs(existing_cookies) do
                    index = index + 1
                    response_cookies[index] = cookie_str
                end
            end
        end
        ngx.header["Set-Cookie"] = response_cookies
    end
end

--clear request cookies
local function _clear_all_request_cookies(session_cookie_name)
    ngx.log(ngx.ERR,"Before clear, request cookies:" .. tostring(ngx.req.get_headers()["Cookie"]))
    local cookies = ngx.req.get_headers()["Cookie"]
    if cookies then
        if session_cookie_name then
            --need to reserve session cookie
            local start_pos = string.find(cookies,session_cookie_name)
            if start_pos then
                --found session cookie
                local end_pos = string.find(cookies, ";", start_pos + 1)
                if end_pos then
                    --not the last cookie
                    cookies = string.sub(cookies, start_pos, end_pos - 1)
                else
                    --is the last cookie
                    cookies = string.sub(cookies, start_pos)
                end
            else
                --not find session cookie
                cookies = nil
            end
        else
            --no need to reserve session cookie
            cookies = nil
        end
    else
        cookies = nil
    end
    ngx.req.set_header("Cookie",cookies)
    ngx.log(ngx.ERR,"After clear, request cookies:" .. tostring(ngx.req.get_headers()["Cookie"]))
end

--Get cookie
local function _get_request_cookie(name)
    local val = ngx.var[name]
    if val and val:len() > 0 then
        return val
    else
        return nil
    end
end

_M.add_response_cookie = _add_response_cookie
_M.set_response_cookie = _set_response_cookie
_M.get_request_cookie = _get_request_cookie
_M.get_all_response_cookies = _get_all_response_cookies
_M.clear_all_cookies = _clear_all_cookies
_M.clear_all_request_cookies = _clear_all_request_cookies

return _M
