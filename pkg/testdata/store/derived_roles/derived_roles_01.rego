package paams.derived_roles.my_derived_roles

derived_roles["admin"] = true {
    input.principal.roles[_] == "admin" 
}

derived_roles["tester"] = true {
    parent_roles := {"dev", "qa"}
    input.principal.roles[_] == parent_roles[_]
}
  
derived_roles["employee_that_owns_the_record"] = true  {
    input.principal.roles[_] == "employee" 
    input.resource.attr.owner == input.principal.id 
}

derived_roles["any_employee"] = true {
    input.principal.roles[_] == "employee" 
}

derived_roles["direct_manager"] = true {
    input.principal.roles[_] == "manager"
    input.resource.attr.geography == input.principal.attr.geography 
    input.resource.attr.geography == input.principal.attr.managed_geographies
}
