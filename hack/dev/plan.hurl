# Plan resources request 1
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
jsonpath "$.meta.filterDebug" == "(((request.resource.attr.geography == \"GB\") AND (request.resource.attr.geography == \"GB\")) AND (request.resource.attr.status == \"PENDING_APPROVAL\"))"


# Plan resources request 2
POST {{protocol}}://{{host}}:{{port}}/api/x/plan/resources
Content-Type: application/json
file,requests/plan_resources/req2.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "defer"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.policyVersion" == "20210210"
jsonpath "$.filter.value" == true
jsonpath "$.meta.filterDebug" == "(true)"
