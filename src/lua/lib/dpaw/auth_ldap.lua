local _M = {}

local ldap = require "lualdap"
local debug = false
local config = {
    ldap_server = "127.0.0.1:389",
    bind_dn = "cn=root",
    bind_password = "root",
    staff_base_dn = "ou=staff",
    staff_filter = "",
    email_attr = "mail",
    account_attr = "sAMAccountName",
    roles_attr = "",
    role_module ="",
    profile_attrs = "email:mail,first_name:first_name,last_name:last_name,name:givenName",
    search_timeout = 5000,
}

local attr_map = {}

local utils = require "dpaw.utils"
local role_module = nil

local function _initialize(config_file)
    local err = nil
    config,err = utils.load_config(config_file,config)
    if not config then
        ngx.log(ngx.ERR,err)
    end

    config.profile_attrs = utils.split(config.profile_attrs,",")

    local attr,ldap_attr,pos = nil,nil,nil
    local index = 0
    for index,v in pairs(config.profile_attrs) do
        v = utils.trim(v)
        pos = string.find(v,":")
        if pos then
            attr = utils.trim(string.sub(v,1,pos - 1))
            ldap_attr = utils.trim(string.sub(v,pos + 1))
        else
            attr = v
            ldap_attr = v
        end

        config.profile_attrs[index] = ldap_attr
        attr_map[ldap_attr] = attr
    end

    index = table.getn(config.profile_attrs)
    --add user roles attribute if not included in profile attributes
    if config.roles_attr ~= nil and string.len(config.roles_attr) > 0 and attr_map[config.roles_attr] == nil then
        attr_map[config.roles_attr] = "user_roles"
        if config.profile_attrs == nil then
            config.profile_attrs = {config.roles_attr}
        else
            index = index + 1
            config.profile_attrs[index] = config.roles_attr
        end
    end

    --add email attribute if not included in profile attributes
    if config.email_attr ~= nil and string.len(config.email_attr) > 0 and attr_map[config.email_attr] == nil then
        attr_map[config.email_attr] = "email"
        if config.profile_attrs == nil then
            config.profile_attrs = {config.email_attr}
        else
            index = index + 1
            config.profile_attrs[index] = config.email_attr
        end
    end

    if config.role_module ~= nil and string.len(config.role_module) > 0 then
        role_module = require(config.role_module)
        if role_module.initialize then
            --has initialize method.
            role_module.initialize(debug)
        end
    end

    if debug then ngx.log(ngx.INFO,"ldap server configuration.\r\n",utils.dict_to_string(config,"    ")) end
end

local function _authenticate(user_name,user_password)
    conn,err = ldap.open_simple(config.ldap_server,config.bind_dn,config.bind_password,false)
    if not conn then
        return false,nil,nil,nil,"Connect to ldap server failed." .. err
    end
    local search_args = {}
    search_args["timeout"] = config.search_timeout
    local user_profile = {}
    local user_roles = nil
    local user_index = 0
    local user_dn = nil
    local users = nil
    local staff_filter = nil
    if config.staff_filter then
        staff_filter = "(&(" .. config.account_attr .. "=" .. user_name  .. ")" .. config.staff_filter .. ")"
    else
        staff_filter = "(" .. config.account_attr .. "=" .. user_name  .. ")"
    end
    for dn,attribs in conn:search {base = config.staff_base_dn,scope="subtree",filter= staff_filter,attrs = config.profile_attrs,sizelimit=2,timeout=config.search_timeout}  do
        if string.sub(dn, 1, 4) ~= "ldap" then
           if debug then ngx.log(ngx.INFO,"user dn = ",dn) end
           if user_index == 0 then
               user_dn = dn
               for name,values in pairs(attribs) do
                    if debug then ngx.log(ngx.INFO,"user_dn = " .. dn .. "," .. name .. " = " .. utils.to_json(values)) end
                    if name == config.roles_attr then
                        if type(values) == "string" then
                            user_roles = {values}
                        elseif type(values) == "table" then
                            user_roles = values
                        end
                    end
                    user_profile[attr_map[name]] = values
                end
                user_index = user_index + 1
            else
                return false,nil,nil,nil,"Multiple user found"
            end
        end
    end
    if not user_dn then
        --user not found
        return false,nil,nil,nil,"User not exist"
    end
    --authenticate user
    conn,err = ldap.open_simple(config.ldap_server,user_dn,user_password,false)
    if not conn then
        --authenticate failed
        return false,nil,nil,nil,"Authentication failed"
    end

    if role_module then
        --configured a role module, get the user_roles from role module
        user_roles = role_module.get_roles(user_name,user_profile)
    end 

    if user_roles == nil then
        --user roles is nil, set to a empty array
        user_roles = {}
    elseif type(user_roles) == "string" then
        --user roles is string, convert it to array
        user_roles = {user_roles}
    end
   
    return true,user_name,user_profile,user_roles,nil
end

--initialize
function _M.initialize(config_file,is_debug)
    debug = is_debug
    return _initialize(config_file)
end

--single sign out
function _M.is_single_sign_out()
    return utils.get_url_arg("ssout") == "true"
end

--  1: authenticate succeed
-- -1: authenticate failed
--  0: authenticating
function _M.authenticate(username,password)
    if debug then ngx.log(ngx.INFO,"Begin to authenticate. user = ",username) end
    if username and password then
        local ok,user,user_profile,user_roles,err = _authenticate(username,password)
        if ok then
            if debug then ngx.log(ngx.INFO,"Authenticate successfully. user = ",user) end
            return 1,user,user_profile,user_roles
        else
            if debug then ngx.log(ngx.INFO,"Authenticate failed. ",err) end
            return -1,nil,nil,nil,err
        end
    else
        return -1,nil,nil,nil,"Missing user name or password "
    end
end

function _M.logout()
end

return _M
