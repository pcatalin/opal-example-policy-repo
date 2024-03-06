package app.rbac

import rego.v1

# By default, deny requests.
default allow := false

# Allow the action if the user is granted permission to perform the action.
allow if {
    some i
    
    input.action == _actions[i]
}

_tenant := x if {
	some tenantData in data.tenants

	tenantData.name == input.tenant
	x := tenantData
}

_role := x if {
	some roleData in _tenant.roles
    
    roleData.name == input.role
    x := roleData
}

_group := x if {
	some groupData in _role.groups
    
    groupData.name == input.group
    x := groupData
}

_actions := x if {
	x := _group.actions
}