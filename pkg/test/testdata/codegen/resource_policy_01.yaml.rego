package paams.resource.leave_request.v20210210

import data.paams.derived_roles.my_derived_roles.derived_roles

default effect = "deny"

effect = "allow" {
    glob.match("*", [], input.action)
    input.principal.roles[_] == "admin"    
}

effect = "allow" {
    glob.match("create", [":"], input.action)
    derived_roles["employee_that_owns_the_record"] == true    
}

effect = "allow" {
	glob.match("view:*", [":"], input.action)
    allowed_roles := {"employee_that_owns_the_record", "direct_manager"}
    some dr
    derived_roles[dr] == true
    allowed_roles[_] == dr     
}

effect = "allow" {
    glob.match("view:public", [":"], input.action)
    derived_roles["any_employee"] == true    
}

effect = "allow" {
    glob.match("approve", [":"], input.action)
    derived_roles["direct_manager"] == true    
    cel_eval(input, "paams.resource.leave_request.v20210210", "cond_0")
}
    

