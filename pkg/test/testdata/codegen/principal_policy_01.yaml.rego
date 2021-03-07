package paams.principal.donald_duck.v20210210

default effect = "no_match"

effect = "allow" {
    glob.match("leave_request", [":"], input.resource.name)
    glob.match("*", [], input.action)
    cel_eval(input, "paams.principal.donald_duck.v20210210", "cond_0")
}

effect = "deny" {
    glob.match("salary_record", [":"], input.resource.name)
    glob.match("*", [], input.action)
}

