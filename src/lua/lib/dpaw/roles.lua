local debug = false

local utils = require "dpaw.utils"
--formats:
-- role has only one condition.
--      role = {
--                 attribute has only one condition
--                 attr1 = {condition},          

--                 attribute has multiple condition, check logic: (condition1 or condition2)
--                 attr2 = {conditon1,condition2},  

--                 attribute has multiple condition,  check logic: ((condition10 and condition11) or (condition20 and condition21))
--                 attr3={ {condition10,condition11},{condition20,condition21} } 
--              }

-- role has multiple condition. but only need to satisfy one of them
--      role = {
--                 {                
--                      attribute has only one condition
--                      attr1 = {condition}          

--                      attribute has multiple condition, check logic: (condition1 or condition2)
--                      attr2 = {conditon1,condition2}  

--                      attribute has multiple condition,  check logic: ((condition10 and condition11) or (condition20 and condition21))
--                      attr3={ {condition10,condition11},{condition20,condition21} }
--                 },
--                 {                
--                      attribute has only one condition
--                      attr1 = {condition}          

--                      attribute has multiple condition, check logic: (condition1 or condition2)
--                      attr4 = {conditon1,condition2}  

--                      attribute has multiple condition,  check logic: ((condition10 and condition11) or (condition20 and condition21))
--                      attr5={ {condition10,condition11},{condition20,condition21} }
--                 },
--              }
local _roles_def = {
    der = {
        objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
        email = {"@der.wa.gov.au$"}
    },
    dpaw = {
        objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
        email = {"@dpaw.wa.gov.au$"}
    },
    cddp = {
        objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
        email = {"@der.wa.gov.au$","@dpaw.wa.gov.au$"}
    },
    bom = {
        objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
        email = {"@der.wa.gov.au$","@dpaw.wa.gov.au$"}
    },
    ga = {
        objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
        email = {"@der.wa.gov.au$","@dpaw.wa.gov.au$"}
    },
    landgate = {
        objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
        email = {"@der.wa.gov.au$","@dpaw.wa.gov.au$"}
    },
    nafi = {
        objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
        email = {"@der.wa.gov.au$","@dpaw.wa.gov.au$"}
    },
    everyone = {
        objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"}
    },
    domain_admins = {
        {
            objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
            memberOf = {"CN=Domain Admins,OU=ICT Administration,OU=Groups,OU=Administrators,DC=corporateict,DC=domain"}
        },
        --or just for developing purpose
        {
            objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
            email = {"^Rocky.Chen@dpaw.wa.gov.au$"}
        },
    },
    --special role for geoserver
    ROLE_ADMINISTRATOR = {
        {
            objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
            memberOf = {"CN=Domain Admins,OU=ICT Administration,OU=Groups,OU=Administrators,DC=corporateict,DC=domain"}
        }, 
        --or just for developing purpose
        {
            objectCategory = {"CN=Person,CN=Schema,CN=Configuration,DC=corporateict,DC=domain"},
            email = {"^Rocky.Chen@dpaw.wa.gov.au$"}
        },
    },
}

local _roles_check = {}

_roles_check.objectCategory = function(user_value,value)
    return user_value == value
end

_roles_check.email = function(user_value,value)
    local matched = string.find(user_value, value) ~= nil
    return matched
end

_roles_check.memberOf = function(user_value,value)
    if type(user_value) == "string" then
        return user_value == value
    elseif type(user_value == "table") then
        for k,v in pairs(user_value) do
            if v == value then
                return true
            end
        end
        return false
    end
    return false
end

local _M = {}

local function _initialize(is_debug)
    debug = is_debug
    --initialize roles_def, and make all roles' conditions will be array type.
    for r,conds in pairs(_roles_def) do
        if not utils.is_array(conds) then
            --not a array, turn it into a array
            _roles_def[r] = {conds}
        end
    end
end

local function _check_cond(attribute,cond,user_name,user_profile) 
    if user_profile[attribute] == nil then
        return false
    end
    if type(cond) == "string" then
        --cond is a string,
        if _roles_check[attribute] then
            --check condition
            return _roles_check[attribute](user_profile[attribute],cond)
        else
            return false
        end
    elseif type(cond) == "table" then
        --cond is a array,only need to match one of them
        for i,cond_member in ipairs(cond) do
            --condition member is a string, check it 
            if type(cond_member) == "string" then
                if _roles_check[attribute] then
                    if _roles_check[attribute](user_profile[attribute],cond_member) then
                        return true
                    end
                end
            elseif type(cond_member) == "table" then
                --condition member is a table, all sub condition in table must be satisfied.
                local matched = true
                for j,sub_cond in ipairs(cond_member) do
                    if _roles_check[attribute] then
                        if not _roles_check[attribute](user_profile[attribute],sub_cond) then
                            matched = false
                            break
                        end
                    else
                        --not support, think it as a failed condition
                        matched = false
                        break
                    end
                end
                if matched then
                    --matched
                    return true
                end
            else
                --not support, think it as a failed condition
            end
        end
        return false
    else
        --not support, think it as a failed condition
        return false
    end
end

local function _get_roles(user_name,user_profile)
    if (user_profile["userAccountControl"] == nil or (tonumber(user_profile["userAccountControl"]) / 2) % 2 == 1)  then
        --disabled
        return {}
    end
    local roles = {}
    local index = 1
    local matched = false
    for r,def in pairs(_roles_def) do
        for i,conds in ipairs(def) do
            matched = true
            for attribute,cond in pairs(conds) do
                if not _check_cond(attribute,cond,user_name,user_profile) then
                    matched = false
                    break
                end
            end
            if matched then
                break
            end
        end
        if matched then
            roles[index] = r
            index = index + 1
        end
    end
    if debug then ngx.log(ngx.INFO,"The roles of the user (".. user_name .. ") is " .. utils.list_to_string(roles)) end
    return roles
end



_M.initialize = _initialize
_M.get_roles = _get_roles

return _M
