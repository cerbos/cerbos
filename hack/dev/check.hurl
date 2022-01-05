# Health endpoint should return 200 with SERVING in the body
GET {{protocol}}://{{host}}:{{port}}/_cerbos/health
HTTP/* 200
[Asserts]
body contains "SERVING"

# Metrics endpoint should return 200 
GET {{protocol}}://{{host}}:{{port}}/_cerbos/metrics
HTTP/* 200

# Valid CheckResourceBatch request
POST {{protocol}}://{{host}}:{{port}}/api/check_resource_batch
Content-Type: application/json
file,requests/check_resource_batch/resource_batch.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.results" count == 2
jsonpath "$.results[?(@.resourceId == 'XX125')].actions[*]" count == 4
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['approve']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['create']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['defer']" == "EFFECT_ALLOW"
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.results[?(@.resourceId == 'XX150')].actions[*]" count == 3
jsonpath "$.results[?(@.resourceId == 'XX150')].actions['approve']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX150')].actions['create']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX150')].actions['view:public']" == "EFFECT_ALLOW"
