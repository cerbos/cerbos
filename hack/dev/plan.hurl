# Plan resources request 1
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req1.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "approve"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.policyVersion" == "20210210"
jsonpath "$.filter" != null
jsonpath "$.meta.filterDebug" == "(eq request.resource.attr.status \"PENDING_APPROVAL\")"
jsonpath "$.cerbosCallId" exists


# Plan resources request 2
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req2.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "defer"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.policyVersion" == "20210210"
jsonpath "$.filter.kind" == "KIND_ALWAYS_ALLOWED"
jsonpath "$.meta.filterDebug" == "(true)"
jsonpath "$.cerbosCallId" exists


# Plan resources request 3
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req3.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "view-as-vip"
jsonpath "$.resourceKind" == "album:object"
jsonpath "$.policyVersion" == "default"
jsonpath "$.filter.kind" == "KIND_CONDITIONAL"
jsonpath "$.meta.filterDebug" == "(eq request.resource.attr.owner \"1\")"
jsonpath "$.cerbosCallId" exists


# Plan resources request 4
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req4.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "view"
jsonpath "$.resourceKind" == "album:object"
jsonpath "$.policyVersion" == "nonexistent"
jsonpath "$.filter.kind" == "KIND_ALWAYS_DENIED"
jsonpath "$.meta.filterDebug" == "(false)"
jsonpath "$.cerbosCallId" exists


# Plan resources request 5 (scoped policies)
POST {{protocol}}://{{host}}:{{port}}/api/plan/resources
Content-Type: application/json
file,requests/plan_resources/req5.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "delete"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.filter.kind" == "KIND_CONDITIONAL"
jsonpath "$.meta.filterDebug" == "(eq request.resource.attr.owner \"john\")"
jsonpath "$.meta.matchedScope" == "acme.hr.uk"
jsonpath "$.cerbosCallId" exists
