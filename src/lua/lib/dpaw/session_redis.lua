local _M = {}

local nginx_session_config = ngx.shared.nginx_session_config

local debug = false
--nginx is single thread process, so at any given time, only one connection can be used, so pool size can be set to 1

--local server_codes = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'}
local server_codes = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'}
local server_code_matrix = nil
local server_code_size = 0

local server_size = 1
local random_upper = 62
local pool_size = 1
local server_configs = nil
local max_idle_time = 3600000
local session_age = nil

local f_access_context = "session.access_context"
local f_session_create_time = "session.create_time"
local f_logout_app = "session.logout_app"
local f_login_url = "session.login_url"
local f_login_time = "session.login_time"

local f_user = "user.name"
local f_user_roles = "user.roles"
local f_user_profile = "user.profile"

local utils = require "dpaw.utils"

--create a unique session id
local uuid4 = require "uuid4"
local function _create_session_key()
    return  uuid4.getUUID()
end

local redis = require "resty.redis"

local redis_server_config_columns = {"host","port","database","password"}

--convert a server index to server code
--server index starts from 1
local function _server_code(server_index)
    return server_codes[math.random(random_upper - 1) * server_size + server_index]
end
--convert a server code to server index
local function _server_index(server_code)
    --if debug then ngx.log(ngx.INFO,"server code is ",server_code) end
    local index = server_code_matrix[server_code] 
    if index then
        return (index - 1) % server_size + 1
    else
        return nil,"incorrect server code. server code = " .. server_code
    end
end
--get a session id from session_key and server_index
local function _encode_session_id(session_key,server_index)
    local code = _server_code(server_index)
    --if debug then ngx.log(ngx.INFO,"encode session id:" .. session_key .. ", " .. code) end
    return session_key .. code
end
--get session key and server index from session id
local function _decode_session_id(session_id)
    --if debug then ngx.log(ngx.INFO,"decode session id:" .. session_id) end
    local server_index,err = _server_index(string.sub(session_id,-1))
    if server_index then
        return string.sub(session_id,1,-2),server_index
    else
        return nil,nil,"Incorrect session id; session id = " .. session_id .. ", err = " .. err
    end
end

--return access token
local function _encode_access_token(session_id,token)
    return token .. "@" .. session_id
end

--return session_id, token
local function _decode_access_token(access_token)
    local start_pos,end_pos = string.find(access_token,"@")
    if start_pos then
        return string.sub(access_token,end_pos + 1),string.sub(access_token,1,start_pos - 1)
    else
        return nil,nil,"incorrect access token; access token = " .. access_token
    end
end

--return true, if it is a access token; otherwise return false
local function _is_access_token(token_or_session)
    local start_pos,end_pos = string.find(access_token,"@")
    if start_pos then
        return true
    else
        return false
    end
end
--return a redis field of an application
local function _app_field_name(app_name)
    return "app." .. app_name
end

--if app name if redis field is an application field; otherwise return nil
local function _app_name(redis_field)
    if string.sub(redis_field,1,4) == "app." then
        --is an application
        return string.sub(redis_field,5)
    else
        --is not an application
        return nil
    end
end

--return a redis field of a token
local function _token_field_name(token_name)
    return "token." .. token_name .. ".access_token"
end

--return a redis field of a token
local function _token_create_time_field_name(token_name)
    return "token." .. token_name .. ".create_time"
end

--return a redis field of a token
local function _token_activate_time_field_name(token_name)
    return "token." .. token_name .. ".create_time"
end

--return a redis field of a token
local function _token_access_context_field_name(token_name)
    return "token." .. token_name .. ".access_context"
end

--return a redis field of a token
local function _token_access_ip_field_name(token_name)
    return "token." .. token_name .. ".access_ip"
end

--load server configure from configure file
local function _load_server_configs(config_file)
    if debug then ngx.log(ngx.INFO,"Begin to load redis server config ",config_file) end
    local redis_file = io.open(config_file,"r")
    io.input(redis_file)
    local redis_file_content = io.read("*a")
    io.close(redis_file)
    local server_configs={}
    local server_index=1
    local column_index = 1
    local config_lines = utils.lines(redis_file_content)
    for i,config_line in pairs(config_lines) do
        column_index = 1
        local server_config = {}
        config_line = utils.trim(config_line)
        if string.len(config_line) > 0 then
            for str in string.gmatch(config_line,'[^%s]+') do
                if redis_server_config_columns[column_index] == "database" then
                    server_config[redis_server_config_columns[column_index]] = tonumber(str)
                elseif redis_server_config_columns[column_index] == "port" then
                    server_config[redis_server_config_columns[column_index]] = tonumber(str)
                else
                    server_config[redis_server_config_columns[column_index]] = str
                end
                column_index = column_index + 1
            end
            if column_index > 1 then
                if debug then ngx.log(ngx.INFO,server_index .. " Redis config row ",utils.dict_to_json(server_config)) end

                if not server_config["host"] or not server_config["port"] then
                    ngx.log(ngx.ERR,"Missing host or port")
                else
                    if not server_config["database"] then
                        server_config["database"] = 0
                    end
                    table.insert(server_configs,server_config)
                    server_index = server_index + 1
                end 
            end
        end
    end
    server_size = table.getn(server_configs)
    if server_size > 0 then
        if debug then ngx.log(ngx.INFO,"Found " .. server_size .. " redis servers.\r\n " .. utils.dict_to_json(server_configs)) end
    
        if table.getn(server_codes) % server_size ~= 0 then
            for i = 1,server_size - table.getn(server_codes) % server_size,1 do
                table.insert(server_codes,server_codes[i])
            end
        end
        random_upper = table.getn(server_codes) / server_size
        server_code_matrix = {}
        for i,code in pairs(server_codes) do
            server_code_matrix[code] = i
        end
    else
        ngx.log(ngx.ERR,"No valid redis server configured.")
    end

    return server_configs;
end

--close a redis connections
local function _close_connection(redis_connection,physically_closed)
    --put  it into the connection pool of size 10, with 1 hour max idle time
    if physically_closed then
        redis_connection:close()
    else
        redis_connection:set_keepalive(max_idle_time,pool_size)
    end
end

--return a redis connections
local function _connect(server_config,check)
    check = check or false

    if not server_config["host"] or not server_config["port"] or not server_config["database"] then
        return nil,"Missing host or port or database."
    end 

    local redis_connection = redis:new()
    redis_connection:set_timeout(1000)
    local ok,err = redis_connection:connect(server_config["host"],server_config["port"])
    if not ok then
        _close_connection(redis_connection,true)
        return nil,"Can not connect to redis server(host = " .. server_config["host"] .. ",port = " .. server_config["port"] .. "). " .. err 
    end

    if server_config["password"] then
        ok,err = redis_connection:auth(server_config["password"])
        if not ok then
            _close_connection(redis_connection,true)
            return nil,"Failed to authenticate to redis server(host = " .. server_config["host"] .. ",port = " .. server_config["port"] .. "). " .. err
        end 
    end

    if server_config["database"] > 0 then
        ok,err = redis_connection:select(server_config["database"])
        if not ok then
            _close_connection(redis_connection,true)
            return nil,"Failed to select a redis database(host = " .. server_config["host"] .. ",port = " .. server_config["port"] .. ", database = " .. server_config["database"] .. " ). " .. err
        end
    end

    if check then
        ok,err = redis_connection:ping()
        if not ok then
            close_redis_connectin(redis_connection,true)
            return nil,"Failed to ping a redis database(host = " .. server_config["host"] .. ",port = " .. server_config["port"] .. ", database = " .. server_config["database"] .. " ). " .. err
        end 
    end

    return redis_connection
end

--get available redis connection
local function _get_available_connection(server_index)
    if server_index then
        local server_config = server_configs[server_index]
        if server_config then
            --maybe the connection is broken, but the server is still alive, try other connections up to pool size.
            for n = 1,pool_size + 1,1 do       
                local redis_connection,err = _connect(server_config,true)
                if redis_connection then
                    return redis_connection,server_index
                else
                    ngx.log(ngx.WARN,"Failed to get a redis connection.",err)
                end
            end
        end
        return nil,nil,"Redis server(" .. utils.dict_to_json(server_configs[server_index])  .. ") is inactive."
    else
        for i,server_config in pairs(server_configs) do
            --maybe the connection is broken, but the server is still alive, try other connections up to pool size.
            for n = 1,pool_size + 1,1 do       
                local redis_connection,err = _connect(server_config,true)
                if redis_connection then
                    return redis_connection,i
                else
                    ngx.log(ngx.WARN,"Failed to get a redis connection.",err)
                end
            end
        end
        return nil,nil,"No active redis server."
    end
end
--get redis connection
local function _get_connection(server_index,try_again)
    if server_size == 0 then
        return nil,nil,"No valid redis server configured."
    elseif server_index and server_size < server_index then
        return nil,nil,"Server index is invalid."
    end
    if try_again then
        if server_index then
            return _get_available_connection(server_index)
        else
            return _get_available_connection(nil)
        end
    else
        if not server_index then
            server_index = math.random(server_size)
            if debug then ngx.log(ngx.INFO,"Try to use the random redis server. index = " .. server_index) end
        end
        local conn,err = _connect(server_configs[server_index],false)
        if conn then
            return conn,server_index,nil
        else
            if debug then ngx.log(ngx.INFO,err) end
            return nil,nil,err
        end
    end
end

--set session data
local function _set_session_data(server_index,key,field,value)
    local ok,err,conn,index = nil,nil,nil,nil
    if debug then ngx.log(ngx.INFO,"Begin to set session data. session_key = " .. key .. ", field = " .. field .. ", value = " .. value .. ".") end
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            ok,err = conn:hset(key,field,value)
            if ok then
                _close_connection(conn,false)
                return true,index,nil
            end
            _close_connection(conn,true)
        end
    end
    ngx.log(ngx.ERR,"Failed to set session data. session_key = " .. key .. ", field = " .. field .. ", value = " .. value .. ".",err)
    return nil,nil,err
end

--remove session data
local function _remove_session_data(server_index,key,field)
    local ok,err,conn,index = nil,nil,nil,nil
    if debug then ngx.log(ngx.INFO,"Begin to remove session data. session_key = " .. key .. ", field = " .. field .. ".") end
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            ok,err = conn:hdel(key,field)
            if ok then
                _close_connection(conn,false)
                return true
            end
            _close_connection(conn,true)
        end
    end
    ngx.log(ngx.ERR,"Failed to remove session data. session_key = " .. key .. ", field = " .. field .. ".", err)
    return false,err
end

--get session data
local function _get_session_data(server_index,key,field)
    local data,err,conn,index = nil,nil,nil,nil
    if debug then ngx.log(ngx.INFO,"Begin to get session data. session_key = " .. key .. ", field = " .. field .. ".") end
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            data,err = conn:hget(key,field)
            if data then
                _close_connection(conn,false)
                if data == ngx.null then
                    return nil,"field (".. field ..") in key (" .. key .. ") not found"           
                else
                    return data
                end
            end
            _close_connection(conn,true)
        end
    end
    ngx.log(ngx.ERR,"Failed to get session data. session_key = " .. key .. ", field = " .. field .. ".", err)
    return nil,err
end

--check whether session exist or not
local function _exists(session_id)
    local result,conn,index,err = nil,nil,nil,nil
    local server_index = nil
    local session_key = nil
    session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return false
    end 
    if debug then ngx.log(ngx.INFO,"Begin to check whether session exist or not . session_key = " .. session_key) end
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            result,err = conn:exists(session_key)
            if result == 1 then
                _close_connection(conn,false)
                if debug then ngx.log(ngx.INFO,"Session exist. session_key = " .. session_key) end
                return true
            elseif result == 0 then
                _close_connection(conn,false)
                if debug then ngx.log(ngx.INFO,"Session does not exist. session_key = " .. session_key) end
                return false
            end
            _close_connection(conn,true)
        end
    end
    return nil,err
end


--create session
local function _create_session(login_url,session_id)
    local ok,conn,index,err = nil,nil,nil,nil
    local server_index = nil
    local session_key = nil
    if session_id then
        session_key,server_index,err = _decode_session_id(session_id)
        if not session_key then
            return nil,err
        end
    else
        session_key = _create_session_key()
    end
    local create_time = os.date("%Y-%m-%d %H:%M:%S")
    if debug then ngx.log(ngx.INFO,"Begin to create session . session_key = " .. session_key .. ", login_url=" ,login_url) end
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            if login_url then
                ok,err = conn:hmset(session_key,f_session_create_time,create_time,f_login_url,login_url)
            else
                ok,err = conn:hset(session_key,f_session_create_time,create_time)
            end
            if ok then
                conn:expire(session_key,session_age)
                _close_connection(conn,false)
                return _encode_session_id(session_key,index),nil
            end
            _close_connection(conn,true)
        end
    end
    return nil,err
end

--remove session
local function _remove_session(server_index,key)
    local ok,conn,index,err = nil,nil,nil,nil
    if debug then ngx.log(ngx.INFO,"Begin to remove session . session_key = " .. key .. ".") end
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            ok,err = conn:del(key,field)
            if ok then
                _close_connection(conn,false)
                return true
            end
            _close_connection(conn,true)
        end
    end
    ngx.log(ngx.ERR,"Failed to remove session . session_key = " .. key .. ".", err)
    return false,err
end

--get registered app
local function _get_registered_apps(server_index,session_key)
    local data,err,conn,index = nil,nil,nil,nil
    if debug then ngx.log(ngx.INFO,"Begin to get registered applications. session_key = " .. session_key .. ". ") end
    local app_name = nil
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            data,err = conn:hgetall(session_key)
            if data then
                _close_connection(conn,false)
                apps = {}
                for i = 1,table.getn(data),2 do
                    app_name = _app_name(data[i])
                    if app_name then
                        apps[app_name] = data[i + 1]
                    end
                end
                if debug then ngx.log(ngx.INFO,"Registered apps ",utils.dict_to_json(apps)) end
                return apps
            end
            _close_connection(conn,true)
        end
    end
    ngx.log(ngx.ERR,"Failed to get registered applications. session_key = " .. session_key .. ". ",err)
    return false,err
end

--check whether app is registered or not
local function _is_app_registered(server_index,session_key,app)
    local result,conn,index,err = nil,nil,nil,nil
    if debug then ngx.log(ngx.INFO,"Begin to check whether app is registered or not . session_key = " .. session_key .. " , app = " .. app) end
    local app_field_name = _app_field_name(app)
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            result,err = conn:hexists(session_key,app_field_name)
            if result == 1 then
                _close_connection(conn,false)
                if debug then ngx.log(ngx.INFO,"App is registered . session_key = " .. session_key .. " , app = " .. app) end
                return true
            elseif result == 0 then
                _close_connection(conn,false)
                if debug then ngx.log(ngx.INFO,"App is not registered . session_key = " .. session_key .. " , app = " .. app) end
                return false
            end
            _close_connection(conn,true)
        end
    end
    return nil,err
end

--set data
local function _save_credential(server_index,key,access_context,user,user_profile,user_roles,expire)
    local ok,err,conn,index = nil,nil,nil,nil
    if debug then ngx.log(ngx.INFO,"Begin to save credential. session key = " .. key .. ", user =" .. user) end

    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            ok,err = conn:hmset(key,f_access_context,access_context,f_user,user,f_user_profile,user_profile,f_user_roles,user_roles,f_login_time,os.date("%Y-%m-%d %H:%M:%S"))
            if ok then
                ok,err = conn:expire(key,expire)
                if ok then
                    _close_connection(conn,false)
                    return true
                end
            end
            _close_connection(conn,true)
        end
    end

    ngx.log(ngx.ERR,"Failed to save credential. session key = " .. key .. ", user =" .. user .. ". ",err)
    return false,err
end


--get user data
local function _get_credential(server_index,session_key)
    local conn,data,err,index = nil,nil,nil,nil
    if debug then ngx.log(ngx.INFO,"Begin to get credential, session key = ",session_key) end
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            data,err = conn:hmget(session_key,f_access_context,f_user,f_user_profile,f_user_roles)
            if data then
                if data == false then
                    --error
                    ngx.log(ngx.ERR,"Get data failed.",err)
                elseif data == ngx.null  or table.getn(data) ~= 4 or 
                        data[1] == nil or type(data[1]) == "userdata" or 
                        data[2] == nil or type(data[2]) == "userdata" or 
                        data[3] == nil or type(data[3]) == "userdata" or 
                        data[4] == nil or type(data[4]) == "userdata" then
                    _close_connection(conn,false)
                    return nil,nil,nil,nil, "Key(" .. session_key .. ") not found"
                else
                    _close_connection(conn,false)
                    return data[1],data[2],data[3],data[4],nil
                end
            end
            _close_connection(conn,true)
        end
    end

    ngx.log(ngx.ERR,"Failed to get credential, session key = " .. session_key .. ". ", err)
    return nil,nil,nil,nil, err
end

--expire user session
local function _renew_credential(server_index,key,expire)
    local conn,ok,err,index = nil,nil,nil,nil
    if debug then ngx.log(ngx.INFO,"Begin to renew credential, session key=" .. key .. ", expire = " .. expire) end
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            ok,err = conn:expire(key,expire)
            if ok then
                _close_connection(conn,false)
                return ok,nil
            end
            _close_connection(conn,true)
        end
    end

    ngx.log(ngx.ERR,"Failed to renew credential, session key=" .. key .. ", expire = " .. expire .. ". ",err)
    return false,err
end

--remove user session
local function _remove_credential(server_index,key)
    if debug then ngx.log(ngx.INFO,"Begin to remove credential, session key=" .. key ) end
    local conn,ok,err,index = nil,nil,nil,nil
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            ok,err = conn:hdel(key,f_user)
            if ok then
                conn:hdel(key,f_access_context)
                conn:hdel(key,f_user_profile)
                conn:hdel(key,f_user_roles)
                _close_connection(conn,false)
                return true
            end
            _close_connection(conn,true)
        end
    end

    ngx.log(ngx.ERR,"Failed to remove credential, session key=" .. key .. ". ",err )
    return false,err
end

--get an access token; only one token per token name;
--if the access token is already exist, return it; otherwise create a new one, and return it.
--token session and associated user session will be in the same redis server.
--this method will assume user session is valid.
local function _get_access_token(session_id,token_name,access_ip)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    if debug then ngx.log(ngx.INFO,"Begin to get access token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name ) end
    local conn,index,err,result = nil,nil,nil,nil,nil
    local token = _create_session_key()
    local token_field_name = _token_field_name(token_name)
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            result,err = conn:hsetnx(session_key,token_field_name,token)
            if result == 1 then
                --app session does not exist, create a new one
                result,err = conn:hmset(session_key,_token_create_time_field_name(token_name),os.date("%Y-%m-%d %H:%M:%S"),_token_access_ip_field_name(token_name),access_ip)
                _close_connection(conn,false)
                if result then
                    -- create successfully
                    if debug then ngx.log(ngx.INFO,"Create a new token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token) end
                    return _encode_access_token(session_id,token)
                else
                    --create failed
                    if debug then ngx.log(ngx.INFO,"Create a new token failed, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token .. " , err = " .. err) end
                    return nil,"Create a new token failed, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token .. " , err = " .. err
                end
            elseif result == 0 then
                --app session exist, retrieve it
                local data = nil
                data,err = conn:hmget(session_key,token_field_name,_token_access_ip_field_name(token_name))
                if data then
                    if data == false then
                        --error
                        _close_connection(conn,false)
                        ngx.log(ngx.ERR,"Get data failed.err = " .. tostring(err))
                        return nil,"Get data failed.err = " .. tostring(err)
                    elseif data == ngx.null  or table.getn(data) ~= 2 or 
                            data[1] == nil or type(data[1]) == "userdata" then
                        _close_connection(conn,false)
                        return nil, "Token(" .. token .. ") not found"
                    else
                        token = data[1]
                        if data[2] == nil or type(data[2]) == "userdata" then
                            --access ip not found, some error happens, recreate it
                            result,err = conn:hmset(session_key,_token_create_time_field_name(token_name),os.date("%Y-%m-%d %H:%M:%S"),_token_access_ip_field_name(token_name),access_ip)
                            _close_connection(conn,false)
                            if result then
                                -- create successfully
                                if debug then ngx.log(ngx.INFO,"Create a new token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token) end
                                return _encode_access_token(session_id,token)
                            else
                                --create failed
                                if debug then ngx.log(ngx.INFO,"Create a new token failed, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token .. " , err = " .. err) end
                                return nil,"Recreate the token failed, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token .. " , err = " .. err
                            end
                        elseif data[2] ~= access_ip then
                            _close_connection(conn,false)
                            if debug then ngx.log(ngx.INFO,"Dismatch between the existing token's access ip and request ip . session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token .. " , request ip = " .. access_ip .. " , expected ip = " .. data[2] ) end
                            --access ip does not match, incorrect request
                            return nil,"access ip does not match. ip = " .. access_ip .. ", expected ip = " .. data[2]
                        else
                            --use the existing token 
                            --remove the access context.
                            local ok,err = conn:hdel(session_key,_token_access_context_field_name(token_name))
                            _close_connection(conn,false)
                            if ok then
                                if debug then ngx.log(ngx.INFO,"Get an existing token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token ) end
                                return _encode_access_token(session_id,token)
                            else
                                if debug then ngx.log(ngx.INFO,"Failed to clear the existing token's access context, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token ) end
                                return nil,"Try to clear the access context failed"
                            end
                        end
                    end
                else
                    _close_connection(conn,true)
                    return nil,err
                end
            end
            _close_connection(conn,true)
        end
    end
    ngx.log(ngx.ERR,"Failed to get access token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. ",err = " .. tostring(err))
    return nil,err
end

--activate an access token;
--return true if succeed; otherwise return false
local function _activate_access_token(token_name,access_token,access_context)
    local session_id,token,err = _decode_access_token(access_token)
    if not session_id then
        --not a valid token, no need to remove
        if debug then ngx.log(ngx.INFO,err) end
        return false,err
    end

    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return false,err
    end

    if debug then ngx.log(ngx.INFO,"Begin to activate access token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. ",access_context = " .. tostring(access_context) ) end
    local conn,index,err,result = nil,nil,nil,nil,nil
    local access_context_field_name = _token_access_context_field_name(token_name)
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            result,err = conn:hsetnx(session_key,access_context_field_name,access_context)
            if result == 1 then
                --not activate before, already activated
                _close_connection(conn,false)
                if debug then ngx.log(ngx.INFO,"End to activate access token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name ) end
                return true
            elseif result == 0 then
                --activate before, get the activate context
                local data = nil
                data,err = conn:hget(session_key,access_context_field_name)
                if data and data ~= ngx.null and data == access_context then
                    _close_connection(conn,false)
                    if debug then ngx.log(ngx.INFO,"Access token is activated before, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name ) end
                    return true
                else
                    _close_connection(conn,false)
                    if debug then ngx.log(ngx.INFO,"The access token's access context and request access contest does not match, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name ) end
                    return false,"Access context does not match"           
                end
            end
            _close_connection(conn,true)
        end
    end
    ngx.log(ngx.ERR,"Failed to activate access token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. ", err = " .. tostring(err) )
    return false,err
end

--remove token
local function _remove_access_token(token_name,access_token)
    local session_id,token,err = _decode_access_token(access_token)
    if not session_id then
        --not a valid token, no need to remove
        if debug then ngx.log(ngx.INFO,err) end
        return true
    end
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        --not a valid session, no need to remove
        if debug then ngx.log(ngx.INFO,err) end
        return true
    end
    if debug then ngx.log(ngx.INFO,"Begin to remove access token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name ) end
    local conn,ok,err = nil,nil,nil,nil
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            ok,err = conn:hdel(session_key,_token_field_name(token_name))
            if ok then
                conn:hdel(session_key,_token_create_time_field_name(token_name))
                conn:hdel(session_key,_token_activate_time_field_name(token_name))
                conn:hdel(session_key,_token_access_context_field_name(token_name))
                conn:hdel(session_key,_token_access_ip_field_name(token_name))
                _close_connection(conn,false)
                return true
            end
            _close_connection(conn,true)
        end
    end

    ngx.log(ngx.ERR,"Failed to remove access token, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name )
    return false,err
end

--get the credential associated with the access token
local function _get_access_token_credential(token_name,access_token)
    local session_id,token,err = _decode_access_token(access_token)
    if not session_id then
        --not a valid token, no need to remove
        if debug then ngx.log(ngx.INFO,err) end
        return nil,nil,nil,nil,nil,nil,err
    end
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        --not a valid session, no need to remove
        if debug then ngx.log(ngx.INFO,err) end
        return nil,nil,nil,nil,nil,nil,err
    end
    if debug then ngx.log(ngx.INFO,"Begin to get access token credential, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name ) end
    local conn,ok,err = nil,nil,nil,nil
    for i = 0,1,1 do
        conn,index,err = _get_connection(server_index,i > 0)
        if conn then
            data,err = conn:hmget(session_key,_token_access_context_field_name(token_name),f_user,f_user_profile,f_user_roles,_token_field_name(token_name),_token_access_ip_field_name(token_name))
            if data then
                if data == false then
                    --error
                    ngx.log(ngx.ERR,"Get data failed.",err)
                elseif data == ngx.null  or table.getn(data) ~= 6 or 
                        data[2] == nil or type(data[2]) == "userdata" or 
                        data[3] == nil or type(data[3]) == "userdata" or 
                        data[4] == nil or type(data[4]) == "userdata" or
                        data[5] == nil or type(data[5]) == "userdata" or
                        data[6] == nil or type(data[6]) == "userdata" then
                    _close_connection(conn,false)
                    if debug then ngx.log(ngx.INFO,"Access token not found, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. ",token = " .. token .. " , [" .. tostring(data[1]) .. "," .. tostring(data[2]) .. "," .. tostring(data[3]) .. "," .. tostring(data[4]) .. "," .. tostring(data[5]) .. "," .. tostring(data[6]) .. "]") end
                    return nil,nil,nil,nil,nil,nil, "Token not found"
                else
                    if data[1] == nil or type(data[1]) == "userdata" then
                        data[1] = nil
                    end
                    _close_connection(conn,false)
                    if data[5] == token then
                        if debug then ngx.log(ngx.INFO,"End to get access token credential, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , user = " .. data[2] .. ", user_profile = " .. data[3] .. " , user_role = " .. data[4]) end
                        return session_id,data[6],data[1],data[2],data[3],data[4],nil
                    else
                        if debug then ngx.log(ngx.INFO,"Access token does not match, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name .. " , token = " .. token .. " , expected token = " .. data[5]) end
                        return nil,nil,nil,nil,nil,nil,err
                    end
                end
            end
            _close_connection(conn,true)
        end
    end

    ngx.log(ngx.ERR,"Failed to get access token credential, session key=" .. session_key .. " , server index=" .. tostring(server_index) .. " , token name = " .. token_name )
    return nil,nil,nil,nil,nil,nil,err
end

--init redis
function _M.initialize(config_file,max_session_age,is_debug)
    debug = is_debug
    server_configs = _load_server_configs(config_file)
    session_age = max_session_age
end

function _M.create_session(login_url,session_key)
    return _create_session(login_url,session_key)
end

function _M.exists(session_key)
    return _exists(session_key)
end

function _M.get_basic_auth_session_id(user_credential)
    local session_key = "B-" .. ngx.encode_base64(ngx.sha1_bin(user_credential))
    return _encode_session_id(session_key,1)
end

function _M.save_credential(session_id,access_context,user,user_profile,user_roles)
    if user == nil then
        user = ""
    end
    if user_profile == nil then
        user_profile = "{}"
    end
    if user_roles == nil then
        user_roles = ""
    end
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end

    return _save_credential(server_index,session_key,access_context,user,user_profile,user_roles,session_age)
end

function _M.renew_credential(session_id)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    return _renew_credential(server_index,session_key,session_age)
end

function _M.remove_credential(session_id)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        --not a valid session, no need to remove
        if debug then ngx.log(ngx.INFO,err) end
        return true
    end
    return _remove_credential(server_index,session_key)
end

function _M.get_credential(session_id)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    return _get_credential(server_index,session_key)
end

function _M.register_app(session_id,application,logout_url)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    if logout_url == nil then
        logout_url = ""
    end
    return _set_session_data(server_index,session_key,_app_field_name(application),logout_url)   
end

function _M.unregister_app(session_id,application)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    return _remove_session_data(server_index,session_key,_app_field_name(application))
end

function _M.get_registered_apps(session_id)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    return _get_registered_apps(server_index,session_key)
end

function _M.is_app_registered(session_id,app)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    return _is_app_registered(server_index,session_key,app)
end

function _M.get_login_url(session_id)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    return _get_session_data(server_index,session_key,f_login_url)
end

function _M.get_logout_app(session_id)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    return _get_session_data(server_index,session_key,f_logout_app)
end

function _M.set_logout_app(session_id,logout_app)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        return nil,err
    end
    return _set_session_data(server_index,session_key,f_logout_app,logout_app)
end

function _M.remove_session(session_id)
    local session_key,server_index,err = _decode_session_id(session_id)
    if not session_key then
        --not a valid session, no need to remove
        if debug then ngx.log(ngx.INFO,err) end
        return true
    end
    return _remove_session(server_index,session_key)
end

function _M.get_access_token(session_id,token_name,access_ip)
    return _get_access_token(session_id,token_name,access_ip)
end

function _M.remove_access_token(token_name,access_token)
    return _remove_access_token(token_name,token)
end

function _M.get_access_token_credential(token_name,token)
    return _get_access_token_credential(token_name,token)
end

function _M.activate_access_token(token_name,access_token,access_context)
    return _activate_access_token(token_name,access_token,access_context)
end


return _M
