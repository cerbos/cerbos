# Plan resources request 1
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req1.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "approve"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.policyVersion" == "20210210"
jsonpath "$.filter" != null
jsonpath "$.meta.filterDebug" == "(request.resource.attr.status == \"PENDING_APPROVAL\")"


# Plan resources request 1 (deprecated endpoint)
POST {{protocol}}://{{host}}:{{port}}/api/x/plan/resources
Content-Type: application/json
file,requests/plan_resources/req1.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "approve"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.policyVersion" == "20210210"
jsonpath "$.filter" != null
jsonpath "$.meta.filterDebug" == "(request.resource.attr.status == \"PENDING_APPROVAL\")"


# Plan resources request 2
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req2.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "defer"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.policyVersion" == "20210210"
jsonpath "$.filter.kind" == "KIND_ALWAYS_ALLOWED"
jsonpath "$.meta.filterDebug" == "(true)"


# Plan resources request 2 (deprecated endpoint)
POST {{protocol}}://{{host}}:{{port}}/api/x/plan/resources
Content-Type: application/json
file,requests/plan_resources/req2.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "defer"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.policyVersion" == "20210210"
jsonpath "$.filter.kind" == "KIND_ALWAYS_ALLOWED"
jsonpath "$.meta.filterDebug" == "(true)"


# Plan resources request 3
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req3.json;
HTTP/* 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.code" == 3
jsonpath "$.message" == "Bad request: missing principal attribute \"vip\""


# Plan resources request 3 (deprecated endpoint)
POST {{protocol}}://{{host}}:{{port}}/api/x/plan/resources
Content-Type: application/json
file,requests/plan_resources/req3.json;
HTTP/* 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.code" == 3
jsonpath "$.message" == "Bad request: missing principal attribute \"vip\""


# Plan resources request 4
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req4.json;
HTTP/* 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.code" == 3
jsonpath "$.message" == "Bad request: no matching policies"


# Plan resources request 4 (deprecated endpoint)
POST {{protocol}}://{{host}}:{{port}}/api/x/plan/resources
Content-Type: application/json
file,requests/plan_resources/req4.json;
HTTP/* 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.code" == 3
jsonpath "$.message" == "Bad request: no matching policies"


# Plan resources request 5 (scoped policies)
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req5.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "delete"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.filter.kind" == "KIND_CONDITIONAL"
jsonpath "$.meta.filterDebug" == "((R.attr.owner == \"john\") AND (true))"
jsonpath "$.meta.matchedScope" == "acme.hr.uk"


# Plan resources request 5 (scoped policies, deprecated endpoint)
POST {{protocol}}://{{host}}:{{port}}/api/x/plan/resources
Content-Type: application/json
file,requests/plan_resources/req5.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "delete"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.filter.kind" == "KIND_CONDITIONAL"
jsonpath "$.meta.filterDebug" == "((R.attr.owner == \"john\") AND (true))"
jsonpath "$.meta.matchedScope" == "acme.hr.uk"
