package paams.principal.donald_duck.v20210210

default effect = "deny"

effect = "allow" {
    glob.match("leave_request", [":"], input.resource.name)
    glob.match("*", [], input.action)
    input.resource.attr.dev_record == true
}

effect = "deny" {
    glob.match("salary_record", [":"], input.resource.name)
    glob.match("*", [], input.action)
}

