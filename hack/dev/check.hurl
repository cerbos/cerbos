# Health endpoint should return 200 with SERVING in the body
GET {{protocol}}://{{host}}:{{port}}/_cerbos/health
HTTP 200
[Asserts]
body contains "SERVING"

# Metrics endpoint should return 200
GET {{protocol}}://{{host}}:{{port}}/_cerbos/metrics
HTTP 200

# Valid CheckResources request 1
POST {{protocol}}://{{host}}:{{port}}/api/check/resources
Content-Type: application/json
file,requests/check_resources/req01.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.results" count == 2
jsonpath "$.results[0].resource.id" == "XX125"
jsonpath "$.results[0].resource.kind" == "leave_request"
jsonpath "$.results[0].resource.policyVersion" == "20210210"
jsonpath "$.results[0].actions[*]" count == 4
jsonpath "$.results[0].actions['approve']" == "EFFECT_DENY"
jsonpath "$.results[0].actions['create']" == "EFFECT_DENY"
jsonpath "$.results[0].actions['defer']" == "EFFECT_ALLOW"
jsonpath "$.results[0].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.results[1].resource.id" == "XX150"
jsonpath "$.results[1].resource.kind" == "leave_request"
jsonpath "$.results[1].resource.policyVersion" == "20210210"
jsonpath "$.results[1].actions[*]" count == 3
jsonpath "$.results[1].actions['approve']" == "EFFECT_DENY"
jsonpath "$.results[1].actions['create']" == "EFFECT_DENY"
jsonpath "$.results[1].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.cerbosCallId" exists

# Valid CheckResources request 2
POST {{protocol}}://{{host}}:{{port}}/api/check/resources
Content-Type: application/json
file,requests/check_resources/req02.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.results" count == 2
jsonpath "$.results[0].resource.id" == "XX125"
jsonpath "$.results[0].resource.kind" == "leave_request"
jsonpath "$.results[0].resource.scope" == "acme.hr.uk"
jsonpath "$.results[0].actions[*]" count == 3
jsonpath "$.results[0].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.results[0].actions['delete']" == "EFFECT_ALLOW"
jsonpath "$.results[0].actions['create']" == "EFFECT_ALLOW"
jsonpath "$.results[1].resource.id" == "XX225"
jsonpath "$.results[1].resource.kind" == "leave_request"
jsonpath "$.results[1].resource.scope" == "acme.hr"
jsonpath "$.results[1].actions[*]" count == 3
jsonpath "$.results[1].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.results[1].actions['delete']" == "EFFECT_DENY"
jsonpath "$.results[1].actions['create']" == "EFFECT_ALLOW"
jsonpath "$.cerbosCallId" exists

# Valid CheckResources request 3
POST {{protocol}}://{{host}}:{{port}}/api/check/resources
Content-Type: application/json
file,requests/check_resources/req03.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.results" count == 1
jsonpath "$.results[0].resource.id" == "XX125"
jsonpath "$.results[0].resource.kind" == "equipment_request"
jsonpath "$.results[0].outputs[0].val.id" == "employee1"

# Invalid CheckResources request 1
POST {{protocol}}://{{host}}:{{port}}/api/check/resources
Content-Type: application/json
file,requests/check_resources/bad_req01.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.results" count == 2
jsonpath "$.results[0].resource.id" == "XX125"
jsonpath "$.results[0].resource.kind" == "leave_request"
jsonpath "$.results[0].resource.policyVersion" == "20210210"
jsonpath "$.results[0].actions[*]" count == 4
jsonpath "$.results[0].actions['approve']" == "EFFECT_DENY"
jsonpath "$.results[0].actions['create']" == "EFFECT_DENY"
jsonpath "$.results[0].actions['defer']" == "EFFECT_DENY"
jsonpath "$.results[0].actions['view:public']" == "EFFECT_DENY"
jsonpath "$.results[0].validationErrors[*]" count == 2
jsonpath "$.results[1].resource.id" == "XX150"
jsonpath "$.results[1].resource.kind" == "leave_request"
jsonpath "$.results[1].resource.policyVersion" == "20210210"
jsonpath "$.results[1].actions[*]" count == 3
jsonpath "$.results[1].actions['approve']" == "EFFECT_DENY"
jsonpath "$.results[1].actions['create']" == "EFFECT_DENY"
jsonpath "$.results[1].actions['view:public']" == "EFFECT_DENY"
jsonpath "$.results[1].validationErrors[*]" count == 2
jsonpath "$.cerbosCallId" exists
