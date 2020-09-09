
local config = {
    app_config_file = "/etc/nginx/app-config",
    --session configure
    session_module = "dpaw.session_redis",
    session_config_file = "/etc/nginx/redis-servers",
    --auth config
    auth_module = "dpaw.auth_redis",
    auth_config_file = "/etc/nginx/ldap-config",


    nginx_session_age = 3600, --seconds

    --declare the constants used by nginx session cookie
    nginx_session_cookie = "NGINX_SESSION",
    nginx_session_arg = "nsessionid",
    nginx_access_token_name_arg = "name",
    nginx_access_token_arg = "token",
    nginx_access_token_name = "ngx_access_token",

    --the request headers injected by nginx.
    user_profile_header = "remote-user-profile",
    user_header = "remote-user",
    user_roles_header = "remote-user-roles",
    user_auth_header = "remote-user-auth",
    nginx_session_header = "nginx_session_id",
    nginx_app_register_status_header = "nginx_app_registered",
    original_cookies = "original_cookies",
    ignore_post_logout = "ignore_post_logout",

    nginx_login_url = "https://sso.dpaw.wa.gov.au/login",
    nginx_logout_url = "https://sso.dpaw.wa.gov.au/logout",
    http_basic_auth_support = false,

    debug = false
}
local url_separator = "\t;\t"
local url_separator_len = string.len(url_separator)

local nginx_session_cookie_var = "cookie_" .. config.nginx_session_cookie
local nginx_session = nil

local auth = nil

local apps_config = {}

local cookie = require "dpaw.cookie"
local utils = require "dpaw.utils"

local function _initialize(config_file)
    local err = nil
    config,err = utils.load_config(config_file,config)
    if not config then
        ngx.log(ngx.ERR,err)
        return
    end
    if config.debug == nil then
        config.debug = false
    end

    if config.debug then ngx.log(ngx.INFO,"Nginix sso configuration.\r\n",utils.dict_to_string(config,"    ")) end

    --load app config
    local configs = utils.load_config(config.app_config_file)
    local appname,appkey,value = nil,nil
    local app_config = nil
    local pos = nil
    for key,value in pairs(configs) do
        pos = string.find(key,"%.")
        if pos then
            appname = string.sub(key,1,pos - 1)
            appkey = string.sub(key,pos + 1)
            app_config = apps_config[appname]
            if app_config == nil then
                app_config = {}
                apps_config[appname] = app_config
            end
            app_config[appkey] = value
        end
    end
    if config.debug then ngx.log(ngx.INFO,"Application configuration.\r\n",utils.dict_to_string(apps_config,"    ")) end

    nginx_session_cookie_var = "cookie_" .. config.nginx_session_cookie

    nginx_session = require(config.session_module)
    nginx_session.initialize(config.session_config_file,config.nginx_session_age,config.debug)

    auth = require(config.auth_module)
    auth.initialize(config.auth_config_file,config.debug)
end

--encode access token from token name and token
local function _encode_access_token(token_name,token)
    return ngx.encode_base64(token_name .. "=" .. token)
end

--decode decode access token to token name and token
local function _decode_access_token(access_token)
    local err = nil
    access_token,err = ngx.decode_base64(access_token)
    if not access_token then
        return nil,nil,"Access token is not a base64 encoded string; err = " .. err
    end
    local start_pos,end_pos = string.find(access_token,"=")
    if start_pos then
        return string.sub(access_token,1,start_pos - 1),string.sub(access_token,end_pos + 1)
    else
        return nil,nil,"incorrect access token; access token = " .. access_token
    end
end

local function _get_app_name() 
    return ngx.var.app
end

--get access context from request
local function _get_access_context()
    return "client_ip:" .. ngx.var.remote_addr .. " browser:" .. tostring(ngx.req.get_headers()["User_Agent"]) .. "\r\n"
end

--get client ip from request
local function _get_access_ip()
    return ngx.var.remote_addr
end

local function _get_uri_cache_key()
    local cache_key = utils.remove_request_arg(ngx.var.request_uri,config.nginx_session_arg)
    if config.debug then ngx.log(ngx.INFO,"Cache key is " .. cache_key) end
    return cache_key
end

local function _get_app_config(app_name,key,default_value) 
    local app_config = apps_config[app_name]
    if app_config then
        if app_config[key] then
            return app_config[key]
        else
            return default_value
        end
    else
        return default_value
    end

end

--get session id from cookie
local function _get_session_id_from_cookie()
    local v = cookie.get_request_cookie(nginx_session_cookie_var)
    if v then
        return v
    else
        return nil,"Not found"
    end
end

local function _get_uri_cache_key()
    local cache_key = utils.remove_request_arg(ngx.var.request_uri,config.nginx_session_arg)
    if config.debug then ngx.log(ngx.INFO,"Cache key is " .. cache_key) end
    return cache_key
end

local function _get_app_config(app_name,key,default_value) 
    local app_config = apps_config[app_name]
    if app_config then
        if app_config[key] then
            return app_config[key]
        else
            return default_value
        end
    else
        return default_value
    end

end

--get session id from cookie
local function _get_session_id_from_cookie()
    local v = cookie.get_request_cookie(nginx_session_cookie_var)
    if v then
        return v
    else
        return nil,"Not found"
    end
end

--return basic user data: user name, password
local function _get_basic_auth_data()
    local user_credential = ngx.req.get_headers()["Authorization"]
    if user_credential and string.sub(user_credential,1,6) == "Basic " then
        user_credential = ngx.decode_base64(string.sub(user_credential,7))
        if user_credential then
            local pos = string.find(user_credential,":")
            if pos then
                --client uses http basic authentication, nginx sso is disalbed for this kind of request.
                if config.debug then ngx.log(ngx.INFO,"Basic Http Authentication. authorization = " .. ngx.req.get_headers()["Authorization"] .. " , user_name = " .. string.sub(user_credential,1,pos - 1)) end
                return user_credential,string.sub(user_credential,1,pos - 1),string.sub(user_credential,pos + 1)
            end
        end
    end
    return nil,nil,nil
end

--Set authentication header which tell backend server that the user is authenticated
local function _set_auth_header(user,user_profile,user_roles,user_auth)
    ngx.req.set_header(config.user_header,user)
    if not user_profile then
        user_profile = "{}"
    end 
    ngx.req.set_header(config.user_profile_header,user_profile)
    ngx.req.set_header(config.user_roles_header,user_roles)
    ngx.req.set_header(config.user_auth_header,user_auth)
end

--remove session cookie in response
local function _post_logout()
    local ignore = ngx.req.get_headers()[config.ignore_post_logout]
    if ignore ~= nil and ignore == "1" then
        if config.debug then ngx.log(ngx.INFO,"This is a user logout request, just redirect to the first application to perform single sign out.") end
    else
        local app_name = _get_app_name()
        cookie.clear_all_cookies(config.nginx_session_cookie,_get_app_config(app_name,"cookie_path"),_get_app_config(app_name,"cookie_domain"))
        --enable cross domain request
        ngx.header["Access-Control-Allow-Origin"] = ngx.req.get_headers()["Origin"]
        ngx.header["Access-Control-Allow-Credentials"] = "true"
    end
end

--set some response header for authenticated request
local function _post_authentication(disable_web_cache,extra_vary_header,register_app)
    if ngx.var.uri == "/logout" then
        --build-in logout, perform post_logout
        _post_logout()
        return
    end

    --enable cross domain request
    ngx.header["Access-Control-Allow-Origin"] = ngx.req.get_headers()["Origin"]
    ngx.header["Access-Control-Allow-Credentials"] = "true"

    if disable_web_cache ~= nil and disable_web_cache == true then
        ngx.header['Cache-Control'] = nil
        utils.patch_header("Vary",extra_vary_header)   
        if config.debug then ngx.log(ngx.INFO,"Vary Header:" .. utils.to_string(ngx.header['Vary'])) end
    end

    --try to get session id from request header which is set by authentication
    local session_id = ngx.req.get_headers()[config.nginx_session_header]
    if session_id then
        if config.debug then ngx.log(ngx.INFO,"get session id from request header.",session_id) end
    else
        session_id = utils.get_url_arg(config.nginx_session_arg)
        if session_id then
            if config.debug then ngx.log(ngx.INFO,"get session id from request uri.",session_id) end
        end
    end

    if session_id then
        local clear_cookies = false
        if register_app and ngx.status > 400 then
            local app_register_status = ngx.req.get_headers()[config.nginx_app_register_status_header]
            if app_register_status == nil or app_register_status ~= "1" then
                -- this is the first request 
                -- the request is failed, clear all the cookies
                clear_cookies = true
            end
        end
        local session_cookie_str = config.nginx_session_cookie .. "=" .. session_id .. "; Path=/"
        if clear_cookies then
            --set the cookie in the response
            cookie.set_response_cookie(session_cookie_str)
        else
            --add the cookie in the response
            cookie.add_response_cookie(session_cookie_str)
        end
        if config.debug then ngx.log(ngx.INFO,"set session id in cookie ",session_id) end
    end
end

--authorization
--user_roles_string is a role list separated by ;
local function _authorization(user_roles_string)
    local roles_string = user_roles_string .. ";"
    --  required_roles: to access this resource, user must have the required roles, for authorization. if nil,no authroization is required.
    --      format:
    --              "role" : fixed role, must be satisfied before accessing
    --              {"role1","role2"} : one dimension array, multiple roles,  check logic: (role1 or role2)
    --              { {"role10","role11"},{"role20","role22"} } : two dimension array, multiple roles; check logic: (role10 and role11) or (role20 and role 21)
    required_roles = ngx.var.roles
    if required_roles == nil then
        --no need to authorization
        return true
    elseif type(required_roles) == "string" then
        --specified one role
        if string.len(required_roles) == 0 then
            return true
        end
        return string.find(roles_string,required_roles .. ";") ~= nil
    elseif type(required_roles) == "table" then
        --multiple aternative roles
        for i,role_member in pairs(required_roles) do
            if type(role_member) == "string" then
                --role_member is one role
                if string.len(role_member) == 0 then
                    return true
                end
                if (string.find(roles_string,role_member .. ";") ~= nil) then
                    return true
                end
            elseif type(role_member) == "table" then
                --role_member is array with multiple required roles
                local matched = true
                for j,sub_role in pairs(role_member) do
                    if (string.find(roles_string,sub_role .. ";") == nil) then
                        matched = false
                        break
                    end
                end
                if matched then
                    return true
                end
            end
        end
        return false
    else
        --not support
        return false
    end
end

local function _logout(fake_url)
    local application = _get_app_name()
    if config.debug then 
        ngx.log(ngx.INFO,"\n\n==========================================================================================\n\n") 
        if fake_url then
            ngx.log(ngx.INFO,"Begin to perform build-in logout" ) 
        else
            ngx.log(ngx.INFO,"Begin to logout" ) 
        end
    end
    if fake_url == nil then
        fake_url = false
    end
    local session_id = _get_session_id_from_cookie()
    local request_access_context = _get_access_context()
    local user,user_profile_json,user_roles_string,access_context = nil,nil,nil,nil

    --logout the http basich auth session first.
    local user_credential,basic_auth_user,basic_auth_password = _get_basic_auth_data()

    if not basic_auth_user then
        --not use basic http authentication, try to get the access token.
        local access_token = utils.get_url_arg(config.nginx_access_token_arg)
        if access_token then
            basic_auth_user = config.nginx_access_token_name
            basic_auth_password = access_token
        end
    end

    if basic_auth_user then
        if basic_auth_user == config.nginx_access_token_name then
            --basic authentication based on access token
            local token_name,token,err = _decode_access_token(basic_auth_password)
            if token_name then
                --verify the requesta
                local token_session_id,access_ip = nil
                token_session_id,access_ip,access_context,user,user_profile_json,user_roles_string,err = nginx_session.get_access_token_credential(token_name,token)
                if token_session_id then
                    if (access_context and request_access_context == access_context) or (not access_context and access_ip == _get_access_ip()) then
                        --valid request
                        --remove token
                        nginx_session.remove_access_token(token_name,token)
                    else
                        if config.debug then ngx.log(ngx.INFO,"Failed to authenticate the logout request") end
                        ngx.exit(ngx.HTTP_BAD_REQUEST)
                        return
                    end
                else
                    --token does not exist.
                end
            else
                --incorrect token
                ngx.exit(ngx.HTTP_BAD_REQUEST)
                return
            end
        else
            --basic authentication based on user name and password
            local basic_auth_session_id = nginx_session.get_basic_auth_session_id(user_credential)
            -- remove nginx session
            nginx_session.remove_session(session_id)
            if session_id and session_id == basic_auth_session_id then
                --logout finished
                ngx.exit(ngx.HTTP_OK)
                return
            end
        end
    end

    local ssout = false
    if not session_id or type(session_id) ~= "string" or not nginx_session.exists(session_id) then
        --session not exist
        if fake_url then
            if config.debug then ngx.log(ngx.INFO,"A fake url, redirect to nginx logout url. ") end
            ngx.redirect(config.nginx_logout_url)
        end
        return
    end

    local logout_app = nginx_session.get_logout_app(session_id)
    if logout_app then
        -- in single sign out mode
        if config.debug then ngx.log(ngx.INFO,"logout app is ",logout_app) end
        ssout = true
    else
        --verify request
        access_context,user,user_profile_json,user_roles_string,err = nginx_session.get_credential(session_id)
        if access_context and access_context ~= request_access_context then
            --access context does not match, incorrect request
            ngx.exit(ngx.HTTP_BAD_REQUEST)
            return
        end

        -- not in single sign out mode
        nginx_session.set_logout_app(session_id,application)
        logout_app = application
        --remove the user authentication information.
        nginx_session.remove_credential(session_id)
        --logout from authentication provider
        auth.logout()
    end
    
    local next_logout_app = nil
    local next_logout_url = nil
    local next_index_url = nil
    local logout_app_index_url = config.nginx_logout_url
    local urls = nil
    local logout_url = nil
    local apps = nil
    local err = nil
    local pos = 0
    if session_id then
        --logout from other applications
        apps,err = nginx_session.get_registered_apps(session_id)
        if apps then
            --try to find the next logout app which is not the logout_app; if can't find, the logout_app will be the next app to logout
            for app,urls in pairs(apps) do
                pos = string.find(urls,url_separator)
                if not pos then
                    --incorrect url
                    nginx_session.unregister_app(session_id,app)
                else
                    logout_url = string.sub(urls,pos + url_separator_len)
                    if app == logout_app then
                        logout_app_index_url = string.sub(urls,1,pos - 1)
                    end
                    if ssout and application == app then
                       --unlikely to happen, the application should already be unregistered before
                        nginx_session.unregister_app(session_id,app)
                    else
                        next_logout_app = app
                        next_index_url = string.sub(urls,1,pos - 1)
                        next_logout_url = logout_url
                        if app ~= logout_app then
                            break
                        end
                    end
                end
            end
        else
            --already logout
            ngx.log(ngx.ERR,"Get registered list failed. ",err)
        end
    end

    if config.debug then 
        if next_logout_app then
            ngx.log(ngx.INFO,"single sign out is " ..  tostring(ssout) .. " , next_logout_app = " .. tostring(next_logout_app) .. " , next_logout_url = " .. tostring(next_logout_url) .. " , next_logout_app_index_url = " .. next_index_url) 
        else
            ngx.log(ngx.INFO,"single sign out is " ..  tostring(ssout) .. " , next_logout_app = null") 
        end
    end
    if ssout then
        if fake_url then
            if config.debug then ngx.log(ngx.INFO,"No need to logout the application (" .. application .. ").") end
        else
            local res = ngx.location.capture(ngx.var.uri,{share_all_vars = true})
            if res.status >= 400 then
                ngx.log(ngx.ERR,"Logout the application (" .. application .. ") failed. status = " .. res.status)
            else
                if config.debug then ngx.log(ngx.INFO,"Logout the application (" .. application .. ") succeed.") end
            end
        end
        if next_logout_app then 
            --have another app to logout
            --unregister the application
            nginx_session.unregister_app(session_id,next_logout_app)
            --single sign out
            if config.debug then ngx.log(ngx.INFO,"Redirect to url (" .. next_logout_url .. ") to logout " .. next_logout_app) end
            if next_logout_app == logout_app then
                ngx.redirect(next_logout_url .. "?redirect_url=" .. ngx.encode_base64(next_index_url))
            else
                ngx.redirect(next_logout_url)
            end
        else
            --no more application to logout
            --remove the session
            nginx_session.remove_session(session_id)
            if application == logout_app then
                --current application is logout app,
                local redirect_url = utils.get_url_arg("redirect_url")
                if redirect_url then
                    redirect_url = ngx.decode_base64(redirect_url)
                else
                    --can not find a login url, use the default one
                    redirect_url = config.nginx_logout_url
                end
                if config.debug then ngx.log(ngx.INFO,"Redirect to url " .. redirect_url) end
                ngx.redirect(redirect_url)
            else
                --current application is not logout app, redirect to nginx_logout_url
                if ngx.var.uri ~= logout_app_index_url then
                    --not nginx logout url, redirect to nginx logout url
                    if config.debug then ngx.log(ngx.INFO,"Redirect to " .. logout_app_index_url) end
                    ngx.redirect(logout_app_index_url)
                end
            end
        end 
    else
        if next_logout_app then
            if next_logout_app == logout_app then
                --only have one registered app
                --remove session
                nginx_session.remove_session(session_id)
                --app logout     
                if fake_url then
                    if config.debug then ngx.log(ngx.INFO,"No need to logout the application (" .. application .. ").") end
                else
                    local res = ngx.location.capture(ngx.var.uri,{share_all_vars = true})
                    if res.status >= 400 then
                        ngx.log(ngx.ERR,"Logout the application (" .. application .. ") failed. status = " .. res.status)
                    else
                        if config.debug then ngx.log(ngx.INFO,"Logout the application (" .. application .. ") succeed.") end
                    end
                end
                if config.debug then ngx.log(ngx.INFO,"Redirect to logout page " .. logout_app_index_url) end
                ngx.redirect(logout_app_index_url)
            else
                --unregister the application
                nginx_session.unregister_app(session_id,next_logout_app)
                --single sign out
                if config.debug then ngx.log(ngx.INFO,"Redirect to url (" .. next_logout_url .. ") to logout " .. next_logout_app) end
                ngx.req.set_header(config.ignore_post_logout,"1")
                ngx.redirect(next_logout_url)
            end
        else
            --no app is required to logout
            --remove session
            nginx_session.remove_session(session_id)
            if ngx.var.uri ~= config.nginx_logout_url then
                --not nginx logout url, redirect to nginx logout url
                if config.debug then ngx.log(ngx.INFO,"Redirect to logout page " .. logout_app_index_url) end
                ngx.redirect(logout_app_index_url)
            end
        end
    end
end

--authenticate the user based on basic http authentication mechanism
--the session created by basic authentication can only shared by backend servers which accessed by user with basic http authentication mechnism
--the session created by basic authentication will not have single sign out feature.
--return basic_auth_session_id,user,user_roles_string,user_profiles_json, if authenticated succeed;otherwise, return nil
local function _basic_authenticate(user_credential,username,password,request_access_context)
    local basic_auth_session_id = nginx_session.get_basic_auth_session_id(user_credential)
    local access_context,user,user_profile_json,user_roles_string,err = nginx_session.get_credential(basic_auth_session_id)
    if user and access_context ~= request_access_context then
        --already authenticated, but access context does not match
        --remove the session
        if config.debug then ngx.log(ngx.INFO,"Already authenticated with http basic authentication mechanism,but access context is not match. user = " .. username .. ", access_context = "..access_context..",request access context = "..request_access_context) end
        nginx_session.remove_session(basic_auth_session_id)
        user = nil
    end
    if user then
        --already authenticated
        if config.debug then ngx.log(ngx.INFO,"Already authenticated with http basic authentication mechanism. user = ",username) end
        --renew the session
        nginx_session.renew_credential(basic_auth_session_id)
    else
        --not authenticated,authenticate with username and password
        local auth_result,user_profile,user_roles,err = 0,nil,nil,nil
        if config.debug then ngx.log(ngx.INFO,"Begin to authenticate with http basic authentication mechanism. user = ",username) end
        auth_result,user,user_profile,user_roles, err = auth.authenticate(username,password)
        if auth_result == 1 then
            user_roles_string = utils.list_to_string(user_roles,";")
            user_profile_json = utils.dict_to_json(user_profile)
            ok,err = nginx_session.save_credential(basic_auth_session_id,_get_access_context(),user,user_profile_json,user_roles_string)
            if not ok then
                --save the session failed
                ngx.log(ngx.ERR,"Save the user session failed. session id = " .. basic_auth_session_id .. ". " .. err )
            else
                if config.debug then ngx.log(ngx.INFO,"Save the user session successfully. session id = ",basic_auth_session_id) end
            end
        elseif auth_result == -1 then
            --authenticate failed
            --ngx.exit(ngx.HTTP_UNAUTHORIZED)
            return nil,nil,nil,nil,"Authenticate failed"
        else
            --authenticating
            ngx.exit(ngx.HTTP_OK)
            return nil,nil,nil,nil,"in authenticating process"
        end
    end
    --authenticated successfully
    return basic_auth_session_id,user,user_profile_json,user_roles_string
end

--authenticate the user with form
local function _authenticate()
    if ngx.req.get_headers()["user_profile_header"] or ngx.req.get_headers()["user_header"] or ngx.req.get_headers()["user_roles_header"] then
        --request already contains the authentication related header, bad request
        ngx.exit(ngx.HTTP_BAD_REQUEST)
        return
    end

    if ngx.req.get_method() == "GET" then
        redirect_url = utils.get_url_arg("redirect_url")
        if redirect_url then
            redirect_url = ngx.decode_base64(redirect_url)
        else
            --can not find a login url, use the default one
            redirect_url = "/"
        end
        if config.debug then 
            ngx.log(ngx.INFO,"\n\n=========================================================================\n\n") 
            ngx.log(ngx.INFO,"After authentication, redirect to url: ",redirect_url) 
        end

        local session_id = utils.get_request_arg(redirect_url,config.nginx_session_arg)
        local session_id_from_args = false
        local cookie_session_id = _get_session_id_from_cookie()
        local ok,err = nil,nil
        if session_id then
            session_id_from_args = true
            if cookie_session_id and cookie_session_id ~= session_id then
                --session id from cookie and session id from request args are mismatched, remove the cookie session id
                nginx_session.remove_session(cookie_session_id)
            end
            if config.debug then ngx.log(ngx.INFO,"Get session id from redirect url.session_id  = " .. session_id) end
        else
            if cookie_session_id then
                if config.debug then ngx.log(ngx.INFO,"Get session id from cookie.session_id  = " .. cookie_session_id) end
                session_id = cookie_session_id
            end
        end

        if session_id then
            access_context,user,user_profile,user_roles,err = nginx_session.get_credential(session_id)
            if user then
                local request_access_context = _get_access_context()
                if access_context ~= request_access_context then
                    --request context mismatch.remove the session
                    nginx_session.remove_session(session_id)
                    user = nil
                end
            end
            if user then
                --already login,use the existing credential.
                if redirect_url then
                    --cross domain redirect, add the session id to the url
                    if not session_id_from_args then
                        if string.find(redirect_url,"?") then
                            redirect_url = redirect_url .. "&" .. config.nginx_session_arg .. "=" .. session_id
                        else
                            redirect_url = redirect_url .. "?" .. config.nginx_session_arg .. "=" .. session_id 
                        end
                    end
                else
                    --redirect to the default login page
                    redirect_url = "/"
                end
                if config.debug then ngx.log(ngx.INFO,"Already login, perform single sign on. session id = " .. session_id .. ",user = " .. user .. ",redirect to url: "..redirect_url) end
                ngx.redirect(redirect_url) 
                return
            else
                --user not login, remove the existing session
                if config.debug then ngx.log(ngx.INFO,"Not authenticated, try to remove the outdated session") end
                if session_id_from_args then
                    --redirect_url has a outdated session id, remove it.
                    redicrect_url = utils.remove_request_arg(redirect_url,config.nginx_session_arg)
                end
                nginx_session.remove_session(session_id)
            end
        end
        --create a new session and return the login page
        if config.debug then ngx.log(ngx.INFO,"Not authenticated, begin to create a new session") end
        session_id,err = nginx_session.create_session(redirect_url)
        if not session_id then
            ngx.log(ngx.ERR,"Failed to create session in redis. session id = ",session_id)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            return
        end
        ngx.req.set_header(config.nginx_session_header,session_id)
        return
    end
    --post method, do the authentication.
    if config.debug then 
        ngx.log(ngx.INFO,"\n\n=========================================================================\n\n") 
        ngx.log(ngx.INFO,"Begin to authenticate the user  ",ngx.var.scheme .. "://" .. ngx.var.http_host  .. ngx.var.uri .. "  Method = " .. ngx.req.get_method()) 
    end

    local err = nil
    local ok = nil
    local user = nil
    local user_profile = nil
    local user_roles = nil
    local access_context = nil
    local redirect_url = nil

    local session_id = _get_session_id_from_cookie()
    if session_id then
        if config.debug then ngx.log(ngx.INFO,"Get session id from cookie. session_id =  " .. session_id) end
        redirect_url,err = nginx_session.get_login_url(session_id)
        if not redirect_url then
            --login url is not found, session is expired
            session_id = nil
        end
    end

    if not session_id then
        --session not exist, create a new one
        session_id,err = nginx_session.create_session("/")
        if not session_id then
            ngx.log(ngx.ERR,"Failed to create session in redis. session id = ",session_id)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            return
        end
    end

    if ngx.req.get_method() ~= "POST" then
        --not post method, redirect to login page
        if not redirect_url then
            redirect_url = "/"
        end
        if config.debug then ngx.log(ngx.INFO,"Authenticate failed.redirect to url: ".. redirect_url .. ", error = Must use HTTP Post method.") end
        ngx.redirect(redirect_url)
        return
    end

    --get username and password
    local auth_result = 0
    local username,password = nil,nil
    local args_table = utils.get_url_args_table()
    ngx.req.read_body()
    local args,err = ngx.req.get_post_args()
    if not args then
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        return
    end
    for key,val in pairs(args) do
        if key =="username" then
            username = val
        elseif key == "userpassword" or key == "password" then
            password = val
        end
    end
    --authenticate with ldap   
    auth_result,user,user_profile,user_roles, err = auth.authenticate(username,password)
    if auth_result == 1 then
        user_roles_string = utils.list_to_string(user_roles,";")
        user_profile_json = utils.dict_to_json(user_profile)
        ok,err = nginx_session.save_credential(session_id,_get_access_context(),user,user_profile_json,user_roles_string)
        if not ok then
            --save the session failed
            ngx.log(ngx.ERR,err)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            return
        end
        if config.debug then ngx.log(ngx.INFO,"Save the user session successfully. session id = ",session_id) end
        ngx.req.set_header(config.nginx_session_header,session_id)
        if redirect_url and redirect_url ~= "/" then
            if string.find(redirect_url,"?") then
                redirect_url = redirect_url .. "&" .. config.nginx_session_arg .. "=" .. session_id
            else
                redirect_url = redirect_url .. "?" .. config.nginx_session_arg .. "=" .. session_id 
            end
        else
            redirect_url = "/"
        end 
        if config.debug then ngx.log(ngx.INFO,"Authenticate successfully, redirect to url " .. redirect_url .. ", session_id = " .. session_id) end
        ngx.redirect(redirect_url)
    elseif auth_result == -1 then
        if not redirect_url then
            redirect_url = "/"
        end
        if config.debug then ngx.log(ngx.INFO,"Authenticate failed.redirect to url: ".. redirect_url .. ", error = " .. err) end
        ngx.redirect(redirect_url)
    else
        --authenticating
        ngx.exit(ngx.HTTP_OK)
    end
end

--Return true, if use basic authentication; otherwise return false
local function _use_basic_authentication()
    if config.debug then ngx.log(ngx.INFO,"Authenticate mechanism is ".. tostring(ngx.var.auth)) end
    if ngx.var.auth == nil or ngx.var.auth ~= 'basic' then
        --not use basic authentication
        return false
    else
        --use basic authentication
        ngx.header['WWW-Authenticate'] = 'Basic realm="DPaW"' 
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.exit(ngx.HTTP_OK)
        return true

    end
end

--verify whether user is authenticated or not
local function _verify_authentication()
    if ngx.var.uri == "/logout" then
        --build-in logout, logout the user
        _logout(true)
        return
    end

    local ok,err = nil,nil
    if auth.is_single_sign_out() then
        --in sigle sign out process
        return
    end

    if config.debug then 
        ngx.log(ngx.INFO,"\n\n==========================================================================================\n\n") 
        ngx.log(ngx.INFO,"Begin to verify authentication for url:  ",ngx.var.scheme .. "://" .. ngx.var.http_host  .. ngx.var.request_uri .. "  Method1 = " .. ngx.req.get_method()) 
    end
    local application = _get_app_name()
    local index_url = _get_app_config(application,"index_url")
    local logout_url = _get_app_config(application,"logout_url")

    if ngx.req.get_headers()["user_profile_header"] or ngx.req.get_headers()["user_header"] or ngx.req.get_headers()["user_roles_header"] then
        --request already contains the authentication related header, bad request
        ngx.exit(ngx.HTTP_BAD_REQUEST)
        return
    end

    local session_id = utils.get_url_arg(config.nginx_session_arg)
    local basic_session_id = nil
    local cookie_session_id = _get_session_id_from_cookie()
    if session_id then
        if config.debug then ngx.log(ngx.INFO,"Get session id from request: ".. session_id) end
        local cookie_session_id = _get_session_id_from_cookie()
        --find session id from cookie
        if cookie_session_id and cookie_session_id ~= session_id then
            --session id from cookie and session id from request args are mismatched, remove the cookie session id
            nginx_session.remove_session(cookie_session_id)
        end
    elseif cookie_session_id then
        session_id = cookie_session_id
        if config.debug then ngx.log(ngx.INFO,"Get session id from cookie: ".. session_id) end
    end

    --get the basic authentication information; 
    local user_credential,basic_auth_user,basic_auth_password = _get_basic_auth_data()
    if basic_auth_user then
        --client uses http basic authentication, nginx sso is disalbed for this kind of request.
        if not config.http_basic_auth_support and not session_id then
            --not login before
            --nginx sso is disalbed for basic authentication. use application to do the authentication.
            if config.debug then ngx.log(ngx.INFO,"The request uses http basic authentication mechanism, nginx sso's basic auth support is disabled .user = "..basic_auth_user .. ", access context = " .. _get_access_context()) end
            return
        else
            --nginx sso is enabled for basic authentication,continue
            if config.debug then ngx.log(ngx.INFO,"The request uses http basic authentication mechanism .user = "..basic_auth_user .. ", access context = " .. _get_access_context()) end
        end
    end

    if not basic_auth_user then
        --not use basic http authentication, try to get the access token.
        local access_token = utils.get_url_arg(config.nginx_access_token_arg)
        if access_token then
            basic_auth_user = config.nginx_access_token_name
            basic_auth_password = access_token
        end
    end


    local user,user_profile_json,user_roles_string,access_context = nil,nil,nil,nil
    local user_auth = "form"
    --try to get session information
    if session_id then
        if type(session_id) ~= "string" then
            --incorrect session id, return
            if config.debug then ngx.log(ngx.INFO,"Session id is incorrect, session_id = ",utils.to_string(session_id)) end
            ngx.exit(ngx.HTTP_BAD_REQUEST)
            return
        end
        if config.debug then ngx.log(ngx.INFO,"Found user session, id = ",session_id) end
        access_context,user,user_profile_json,user_roles_string,err = nginx_session.get_credential(session_id)
    else
        if config.debug then ngx.log(ngx.INFO,"No session id found.") end
    end

    if user then
        if config.debug then ngx.log(ngx.INFO,"Found user session user = ",user .. ', user profile = ' ..user_profile_json .. ', user roles = ' .. user_roles_string) end
        --already authenticated
        --validate whether the request access context is the same as the session's access context
        local request_access_context = _get_access_context()
        if (access_context == request_access_context) then
            if basic_auth_user and basic_auth_user == config.nginx_access_token_name then
                local token_name,token = _decode_access_token(basic_auth_password)
                local token_session_id,token_access_ip,token_access_context,token_user,token_user_profile_json,token_user_roles_string = nil,nil,nil,nil,nil,nil
                token_session_id,token_access_ip,token_access_context,token_user,token_user_profile_json,token_user_roles_string,err = nginx_session.get_access_token_credential(token_name,token)
                if token_session_id then
                    if (token_session_id ~= session_id) then
                        --cookie session and token session don't match.
                        ngx.remove_session(token_session_id)
                        ngx.exit(ngx.HTTP_BAD_REQUEST)
                        return
                    elseif (token_access_context and token_access_context == request_access_context) or (not token_access_context and token_access_ip == _get_access_ip()) then
                        if not token_access_context then
                            --activate the token
                            if not nginx_session.activate_access_token(token_name,token,request_access_context) then
                                --activate failed
                                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                                return
                            end
                        end
                        user_auth = "token"
                        nginx_session.renew_credential(session_id)
                    elseif _use_basic_authentication() then
                        --use basic authentication
                        return
                    else
                        --failed
                        ngx.exit(ngx.HTTP_UNAUTHORIZED)
                        return
                    end
                elseif _use_basic_authentication() then
                    --use basic authentication
                    return
                else
                    --failed
                    ngx.exit(ngx.HTTP_UNAUTHORIZED)
                    return
                end
            elseif basic_auth_user and basic_auth_user ~= user then
                --use http basci mechanism, and have different user name. use multiple session
                basic_session_id,user,user_profile_json,user_roles_string,err = _basic_authenticate(user_credential,basic_auth_user,basic_auth_password,request_access_context)
                if basic_session_id then
                    --succeed, renew the session
                    nginx_session.renew_credential(session_id)
                    session_id = basic_session_id
                    user_auth = "basic"
                elseif _use_basic_authentication() then
                    --use basic authentication
                    return
                else
                    --failed
                    ngx.exit(ngx.HTTP_UNAUTHORIZED)
                    return
                end
            else
                --not use http basic mechanism or use http basic mechanism, but have the same user name
                --renew the session
                nginx_session.renew_credential(session_id)
            end
        else
            --access context mismatch, logout
            if config.debug then ngx.log(ngx.INFO,"Session access context does not match. user = " .. user ..  ",access context =  " .. access_context .. ", request access context = "..request_access_context) end
            if _use_basic_authentication() then
                return
            elseif logout_url then
                ngx.redirect(logout_url)
            else
                ngx.redirect("/logout")
            end
            return
        end
    elseif basic_auth_user and basic_auth_user == config.nginx_access_token_name then
        local request_access_context = _get_access_context()
        local token_name,token = _decode_access_token(basic_auth_password)
        local access_ip = nil
        session_id,access_ip,access_context,user,user_profile_json,user_roles_string,err = nginx_session.get_access_token_credential(token_name,token)
        if session_id then
            if (access_context and access_context == request_access_context) or (not access_context and access_ip == _get_access_ip()) then
                if not access_context then
                    --activate the token
                    ngx.log(ngx.ERR,"session_id= " .. session_id)
                    if not nginx_session.activate_access_token(token_name,token,request_access_context) then
                        --activate failed
                        ngx.exit(ngx.HTTP_UNAUTHORIZED)
                        return
                    end
                end
                user_auth = "token"
                nginx_session.renew_credential(session_id)
            elseif _use_basic_authentication() then
                --use basic authentication
                return
            else
                --failed
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
                return
            end
        elseif _use_basic_authentication() then
            --use basic authentication
            return
        else
            --failed
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
            return
        end
    elseif basic_auth_user then
        --user not login, and use http basci mechanism,
        local request_access_context = _get_access_context()
        basic_session_id,user,user_profile_json,user_roles_string,err = _basic_authenticate(user_credential,basic_auth_user,basic_auth_password,request_access_context)
        if basic_session_id then
            --succeed
            session_id = basic_session_id
            user_auth = "basic"
        elseif _use_basic_authentication() then
            --use basic authentication
            return
        else
            --failed
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
            return
        end
    elseif _use_basic_authentication() then
        --use http basic authentication
        if config.debug then ngx.log(ngx.INFO,"Not authenticated, use http basic authentication.") end
        return
    else
        --user not login
        if config.debug then ngx.log(ngx.INFO,"Not authenticated, redirect to login page") end
        if session_id then
            nginx_session.remove_session(session_id)
        end
        
        --not authentication,
        if ngx.req.get_method() == "GET" then
            --is a get request, after login, nginx will redirect to that url automatically
            local redirect_url = ngx.var.scheme .. "://" .. ngx.var.http_host  .. utils.remove_request_arg(ngx.var.request_uri,config.nginx_session_arg)
            if config.debug then ngx.log(ngx.INFO,"After authentication, redirect to url: " .. redirect_url) end
            --add timestamp to prevent the browser from using the cached content.
            ngx.redirect(config.nginx_login_url .. "?redirect_url=" .. ngx.encode_base64(redirect_url) .. "&timestamp=" .. ngx.now())
        else
            ngx.redirect(config.nginx_login_url .. "?timestamp=" .. ngx.now())
        end
        return
    end
    --authenticated successfully.

    --authorization
    if _authorization(user_roles_string) then
        _set_auth_header(user,user_profile_json,user_roles_string,user_auth)
    elseif _use_basic_authentication() then
        -- use http basic authentication
        return
    else
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
        return
    end

    --check whether app is registered or not
    if nginx_session.is_app_registered(session_id,application) then
        --registered
        ngx.req.set_header(config.nginx_app_register_status_header,"1")
    else
        --not registered
        ngx.req.set_header(config.nginx_app_register_status_header,"0")
        --remove the cookies to prevent the backend server from using existing session
        --save the original cookies which can be used to clear cookies when request failed
        ngx.req.set_header(config.original_cookies,ngx.req.get_headers()["Cookie"])
        cookie.clear_all_request_cookies(config.nginx_session_cookie)

        --register the app
        local app_url = nil
        if user_auth == "basic" then
            app_url = "" .. url_separator .. ""
        else
            if index_url then
                if (string.len(index_url) > 5 and string.lower(string.sub(index_url,1,5)) == "http:") or (string.len(index_url) > 6 and string.lower(string.sub(index_url,1,6)) == "https:") then
                    app_url = index_url
                else
                    app_url = ngx.var.scheme .. "://" .. ngx.var.http_host .. index_url
                end
            else
                app_url = config.nginx_logout_url
            end
            app_url = app_url .. url_separator
            if logout_url then
                if (string.len(logout_url) > 5 and string.lower(string.sub(logout_url,1,5)) == "http:") or (string.len(logout_url) > 6 and string.lower(string.sub(logout_url,1,6)) == "https:") then
                    app_url = app_url .. logout_url
                else
                    app_url = app_url .. ngx.var.scheme .. "://" .. ngx.var.http_host .. logout_url
                end
            else
                app_url = app_url .. ngx.var.scheme .. "://" .. ngx.var.http_host .. "/logout"
            end
        end
        if config.debug then ngx.log(ngx.INFO,"Begin to register the application (" .. application .. "), url = " .. tostring(app_url )) end
        ok,err = nginx_session.register_app(session_id,application,app_url)
        if not ok then
            --register application failed
            ngx.log(ngx.ERR,"Failed to register the application (" .. application .. ")")
        end
    end

    --build-in url: get access key 
    if ngx.var.uri == "/get_access_token" then
        token_name = utils.get_url_arg(config.nginx_access_token_name_arg)
        if token_name then
            local token,err = nginx_session.get_access_token(session_id,token_name,_get_access_ip())
            if token then
                --get token successfully
                ngx.header["Content-Type"] = "application/vnd.geo+json"
                ngx.status = ngx.HTTP_OK
                local body = '{"name":"' .. config.nginx_access_token_name .. '","token":"' .. _encode_access_token(token_name,token)  .. '"}'
                ngx.print(body)
                return
            else
                --get token failed
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
                return
            end
        else
            --app name not found, error
            ngx.exit(ngx.HTTP_BAD_REQUEST)
            return
        end
    end
end

local _M = {}
--initialize the sso module,
--in http section
function _M.initialize(config_file)
    return _initialize(config_file)
end
--verify whether user is authenticated or not.
--in application's location section
function _M.verify_authentication()
    return _verify_authentication()
end
--authenticate user with http form
-- in nginx login app location section.
function _M.authenticate()
    return _authenticate()
end
--perform after authentication
--args
--      disable_web_cache : set response header to disable web cache feature;
--      extra_vary_header : add to the vary header;
-- location section
function _M.post_authentication(disable_web_cache,extra_vary_header)
    return _post_authentication(disable_web_cache,extra_vary_header,false)
end

--perform after verify authentication
--args
--      disable_web_cache : set response header to disable web cache feature;
--      extra_vary_header : add to the vary header;
-- location section
function _M.post_verify(disable_web_cache,extra_vary_header)
    return _post_authentication(disable_web_cache,extra_vary_header,true)
end

--perform after logout
-- location section
function _M.post_logout()
    return _post_logout()
end
--perform logout
--location section
function _M.logout()
    return _logout(false)
end

--remove nginx session id from url to make sure the content shared by all users
function _M.get_uri_cache_key()
    return _get_uri_cache_key()
end

return _M

