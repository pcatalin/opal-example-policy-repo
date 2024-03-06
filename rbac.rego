# Role-based Access Control (RBAC)
# --------------------------------
#
# This example defines an RBAC model for a Pet Store API. The Pet Store API allows
# users to look at pets, adopt them, update their stats, and so on. The policy
# controls which users can perform actions on which resources. The policy implements
# a classic Role-based Access Control model where users are assigned to roles and
# roles are granted the ability to perform some action(s) on some type of resource.
#
# This example shows how to:
#
#	* Define an RBAC model in Rego that interprets role mappings represented in JSON.
#	* Iterate/search across JSON data structures (e.g., role mappings)
#
# For more information see:
#
#	* Rego comparison to other systems: https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/
#	* Rego Iteration: https://www.openpolicyagent.org/docs/latest/#iteration

package app.rbac
import future.keywords.in
import future.keywords.if

# import data.utils

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