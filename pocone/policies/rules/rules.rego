package rules

import data.dataset
import input.attributes.request.http as http_request

# groups_permissions assignments
permissions := {
    "admin"    :  	  [{"action": "POST"},
    				   {"action": "GET"},
                       {"action": "DELETE"},
                       {"action": "PUTT"}],                      
    "engineer":       [{"action": "POST"},
    				   {"action": "GET"},
                       {"action": "PUT"}],
    "user"     :      [{"action": "GET"}]
}

resources_path := {
	"admin_resource" : {"resource": "/admin_rest_api"},
    "op_resource"	 : {"resource": "/operation_api"},
    "user_resource"  : {"resource": "/query_api"}
}

access_control_list := {
    "admins_acl" 	 : {permissions.admin, resources_path.admin_resource, resources_path.op_resource, resources_path.user_resource},
    "operations_acl" : {permissions.engineer, resources_path.op_resource, resources_path.user_resource},
    "users_acl"		 : {permissions.user, resources_path.user_resource}
}

users_list := {
    "eve"  : access_control_list.admins_acl,
    "adam" : access_control_list.operations_acl,
    "mary" : access_control_list.users_acl
}
    
default allow = false

allow {
	
   check_is_permited
   
}

check_is_permited {

	user := http_request.user
    path := http_request.path
    action:= http_request.method
    
    acl := users_list

    some x ;acl[x]

    a := x == user

    b := acl[user][_].resource == path
    
    c := acl[user][_][_].action == action
    
}