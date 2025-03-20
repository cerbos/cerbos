# X-scope plan resources request 1
POST {{protocol}}://{{host}}:{{port}}/api/plan/x-scope-resources
Content-Type: application/json
file,requests/x_scope_plan_resources/req1.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "approve"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.policyVersion" == "20210210"
jsonpath "$.filter" != null
jsonpath "$.meta.filterDebug" == "(and (eq request.resource.scope \"\") (eq request.resource.attr.status \"PENDING_APPROVAL\"))"
jsonpath "$.cerbosCallId" exists

# X-scope plan resources request 2
POST {{protocol}}://{{host}}:{{port}}/api/plan/x-scope-resources
Content-Type: application/json
file,requests/x_scope_plan_resources/req2.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.action" == "approve"
jsonpath "$.resourceKind" == "leave_request"
jsonpath "$.policyVersion" == "20210210"
jsonpath "$.filter" != null
jsonpath "$.meta.filterDebug" == "(and (in request.resource.scope [\"abc\",\"def\"]) (eq request.resource.attr.status \"PENDING_APPROVAL\"))"
jsonpath "$.cerbosCallId" exists
