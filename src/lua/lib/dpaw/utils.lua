--check whether the table d is a array
--return true if key is number, and start from 1.
local _M = {}
local function _is_array(d)
    local max_index = 0
    local len = 0
    for k,v in pairs(d) do
        if type(k) ~= "number" then
            return false
        end
        if k <= 0 then
            --index start from 1
            return false
        end
        len = len + 1
        if k > max_index then
            max_index = k
        end
    end
    return max_index == len
end

local function _to_json(o)
    if o == nil then
        return ""
    elseif type(o) == "string" then
        return "\"" .. o .. "\""
    elseif type(o) == "table" then
        if _M.is_array(o) then
            return _M.list_to_json(o)
        else
            return _M.dict_to_json(o)
        end
    else
        return tostring(o)
    end
end
--return array d as a json string
local function _list_to_json(d)
    local list_json = ""
    for i = 1,table.getn(d) ,1 do
        if i == 1 then
            list_json =  _M.to_json(d[i])
        else
            list_json = list_json .. ", " .. _M.to_json(d[i]) 
        end
    end
    return "[" .. list_json .. "]"
end
--return table d as json string
local function _dict_to_json(d)
    local json_str = ""
    if d then
        for k,v in pairs(d) do
            if json_str == "" then
                json_str = "\"" .. k .. "\":"
            else
                json_str = json_str .. ", " .. "\"" .. k .. "\":"
            end
            json_str = json_str ..  _M.to_json(v)
        end
    end
    return "{" .. json_str .. "}"
end

local function _to_string(o,prefix)
    if prefix == nil then
        prefix = ""
    end
    if o == nil  then
        return ""
    elseif type(o) == "string" then
        return "\"" .. o .. "\""
    elseif type(o) == "table" then
        if _M.is_array(o) then
            return _M.list_to_string(o)
        else
            return _M.dict_to_string(o,prefix)
        end
    else
        return tostring(o)
    end
end
--return array d as a json string

--return array l as string
local function _list_to_string(l,separator)
    if not separator then
        separator = ","
    end
    local str = ""
    if l then
        for k,v in pairs(l) do
            if str == "" then
                str = v 
            else
                str = str .. separator .. v 
            end
        end
    end
    return str
end

--return table l as string
local function _dict_to_string(l,prefix)
    if  prefix == nil then
        prefix = ""
    end
    local str = ""
    local separator = "\r\n"
    if l then
        local str = ""
        local separator = "\r\n"
        for k,v in pairs(l) do
            if str ~= "" then
                str = str .. separator
            end
            str = str .. prefix  .. k .. " = " .. _M.to_string(v,prefix .. "    ")
        end
        return str
    else
        return ""
    end
end

local function _trim(s)
    return s:match "^%s*(.-)%s*$"
end

--Get url args table
local function _get_url_args_table()
    local args = ngx.req.get_uri_args()
    local t = {}
    for key,val in pairs(args) do
        t[key] = val
    end
    return t
end

--Get url args table
local function _get_url_arg(arg)
    return ngx.req.get_uri_args()[arg]
end

--split a string into lines
local function _lines(str)
  local t = {}
  local function _helper(line) table.insert(t, line) return "" end
  _helper((str:gsub("(.-)\r?\n", _helper)))
  return t
end

local function _split(str,separator)
    if not separator then
        separator = ","
    end

    local pattern = string.format("([^%s]+)", separator)
    local fields = {}
    str:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

--parse a property file and return a table
local function _load_config(config_file,default_config)
    local config_file,err = io.open(config_file,"r")
    if not config_file then
        return nil,"Fail to load property file '" .. config_file .."'." .. err
    end
    io.input(config_file)
    local config_file_content = io.read("*a")
    io.close(config_file)

    local config_lines = _M.lines(config_file_content)
    local pos,key,value = nil,nil,nil
    local config = nil
    config = {}
    if default_config then
        --copy all data from default
        for k,v in pairs(default_config) do
            config[k] = v
        end
    end
    local is_string = false
    for i,config_line in pairs(config_lines) do
        config_line = _M.trim(config_line)
        if string.len(config_line) == 0 then
            --empty line
        elseif string.sub(config_line,1,1) == "#" then
            --comment line
        else
            pos = string.find(config_line,"=")
            if pos then
                key = _M.trim(string.sub(config_line,1,pos - 1))
                value = _M.trim(string.sub(config_line,pos + 1))
                is_string = false
                if string.len(value) >= 2 then
                    --if the value is in a double quote or single quote, remove it
                    if (string.sub(value,1,1) == "\"" and string.sub(value,-1,-1) == "\"" ) or (string.sub(value,1,1) == "'" and string.sub(value,-1,-1) == "'") then
                        value = _M.trim(string.sub(value,2,-2))
                        is_string = true
                    end
                end
                --type conversion
                if is_string then
                    value = value
                else
                    local lvalue = string.lower(value)
                    if lvalue == "true" or lvalue == "on" or lvalue == "yes" or lvalue == "y" or lvalue == "t" then
                        value = true
                    elseif lvalue == "false" or lvalue == "off" or lvalue == "no" or lvalue == "n" or lvalue == "f" then
                        value = false
                    elseif lvalue == "null" or lvalue == "nil" then
                        value = nil
                    else
                        value = tonumber(value)
                    end
                end
                if default_config then
                    --have default config, replaced the default config with the customized configuration
                    --if customized configuration is not contained in default config, it is ignored.
                    if config[key] ~= nil then
                        config[key] = value
                    else
                        --not recoginzed, ignore
                        ngx.log(ngx.WARN,"The config item (" .. key .. " = " .. value ..") is not recognized and ignored.")
                    end
                else
                    --no default config
                    if value ~= nil then
                        config[key] = value
                    end
                end
            end
        end
    end
    return config,nil
end

local function _remove_request_arg(query_uri,arg)
    if query_uri == nil then
        query_uri = ""
    end
    
    local start_pos = query_uri:find(arg)
    if start_pos then
        local end_pos = query_uri:find("&",start_pos)
        if start_pos == 1 then
            if end_pos then
                query_uri = query_uri.sub(end_pos + 1)
            else
                query_uri = ""
            end
        else
            if end_pos then
                query_uri = query_uri:sub(1,start_pos - 1) .. query_uri.sub(end_pos + 1)
            else
                query_uri = query_uri:sub(1,start_pos - 2)
            end
        end
    end
    return query_uri
end

local function _get_request_arg(query_uri,arg)
    if query_uri == nil then
        return nil
    end
    arg = arg .. "="
    local start_pos = query_uri:find(arg)
    if start_pos then
        local end_pos = query_uri:find("&",start_pos)
        if end_pos then
            return query_uri:sub(start_pos + arg:len(),end_pos - 1)
        else
            return query_uri:sub(start_pos + arg:len())
        end
    else
        return nil
    end
end

local function _patch_header(header_name,extra_header)
    if extra_header ~= nil then
        local header = ngx.header[header_name]
        if header == nil then
            if type(extra_header) == "string" then
                header = {extra_header}
            else
                header = extra_header
            end
        else
            if type(header) == "string" then
                header = {header}
            end

            if type(extra_header) == "string" then
                local size = #header
                local found = false
                for i = 1,size do
                    if header[i] == extra_header then
                        found = true
                    end
                end
                if not found then
                    header[size + 1] = extra_header
                end
            else
                local extra_size = #extra_header
                local found = false
                local size = nil
                for i = 1,extra_size do
                    size = #header
                    found = false
                    for j = 1,size do
                        if header[j] == extra_header[i] then
                            found = true
                        end
                    end
                    if not found then
                        header[size + 1] = extra_header[i]
                    end
                end
            end
        end

        ngx.header[header_name] = header
    end
end
--initialize
_M.is_array = _is_array
_M.to_json = _to_json
_M.list_to_json = _list_to_json
_M.dict_to_json = _dict_to_json
_M.list_to_string = _list_to_string
_M.dict_to_string = _dict_to_string
_M.to_string = _to_string
_M.trim = _trim
_M.get_url_args_table = _get_url_args_table
_M.get_url_arg = _get_url_arg
_M.lines = _lines
_M.load_config = _load_config
_M.split = _split
_M.patch_header = _patch_header
_M.remove_request_arg = _remove_request_arg
_M.get_request_arg = _get_request_arg
return _M
