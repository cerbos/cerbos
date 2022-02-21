# Health endpoint should return 200 with SERVING in the body
GET {{protocol}}://{{host}}:{{port}}/_cerbos/health
HTTP/* 200
[Asserts]
body contains "SERVING"

# Metrics endpoint should return 200 
GET {{protocol}}://{{host}}:{{port}}/_cerbos/metrics
HTTP/* 200

# Valid CheckResourceSet request
POST {{protocol}}://{{host}}:{{port}}/api/check
Content-Type: application/json
file,requests/check_resource_set/req01.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.resourceInstances[*]" count == 5
jsonpath "$.resourceInstances['XX125'].actions[*]" count == 4
jsonpath "$.resourceInstances['XX125'].actions['approve']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX125'].actions['create']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX125'].actions['defer']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['XX125'].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.meta.resourceInstances['XX125'].effectiveDerivedRoles" count == 1
jsonpath "$.meta.resourceInstances['XX125'].effectiveDerivedRoles[0]" == "any_employee"
jsonpath "$.meta.resourceInstances['XX125'].actions['approve'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX125'].actions['create'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX125'].actions['defer'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX125'].actions['view:public'].matchedPolicy" == "resource.leave_request.v20210210"

jsonpath "$.resourceInstances['XX150'].actions[*]" count == 4
jsonpath "$.resourceInstances['XX150'].actions['approve']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX150'].actions['create']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX150'].actions['defer']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['XX150'].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.meta.resourceInstances['XX150'].effectiveDerivedRoles" count == 1
jsonpath "$.meta.resourceInstances['XX150'].effectiveDerivedRoles[0]" == "any_employee"
jsonpath "$.meta.resourceInstances['XX150'].actions['approve'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX150'].actions['create'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX150'].actions['defer'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX150'].actions['view:public'].matchedPolicy" == "resource.leave_request.v20210210"

jsonpath "$.resourceInstances['XX250'].actions[*]" count == 4
jsonpath "$.resourceInstances['XX250'].actions['approve']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX250'].actions['create']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX250'].actions['defer']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['XX250'].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.meta.resourceInstances['XX250'].effectiveDerivedRoles" count == 1
jsonpath "$.meta.resourceInstances['XX250'].effectiveDerivedRoles[0]" == "any_employee"
jsonpath "$.meta.resourceInstances['XX250'].actions['approve'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX250'].actions['create'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX250'].actions['defer'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX250'].actions['view:public'].matchedPolicy" == "resource.leave_request.v20210210"

jsonpath "$.resourceInstances['YY100'].actions[*]" count == 4
jsonpath "$.resourceInstances['YY100'].actions['approve']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY100'].actions['create']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY100'].actions['defer']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY100'].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.meta.resourceInstances['YY100'].actions['approve'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY100'].actions['create'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY100'].actions['defer'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY100'].actions['view:public'].matchedPolicy" == "principal.donald_duck.v20210210"

jsonpath "$.resourceInstances['YY200'].actions[*]" count == 4
jsonpath "$.resourceInstances['YY200'].actions['approve']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY200'].actions['create']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY200'].actions['defer']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY200'].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.meta.resourceInstances['YY200'].actions['approve'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY200'].actions['create'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY200'].actions['defer'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY200'].actions['view:public'].matchedPolicy" == "principal.donald_duck.v20210210"

# Valid CheckResourceSet request (scoped policies)
POST {{protocol}}://{{host}}:{{port}}/api/check
Content-Type: application/json
file,requests/check_resource_set/req02.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.resourceInstances['XX125'].actions[*]" count == 3
jsonpath "$.resourceInstances['XX125'].actions['approve']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX125'].actions['delete']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['XX125'].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.meta.resourceInstances['XX125'].effectiveDerivedRoles" count == 2
jsonpath "$.meta.resourceInstances['XX125'].effectiveDerivedRoles" includes "employee_that_owns_the_record"
jsonpath "$.meta.resourceInstances['XX125'].effectiveDerivedRoles" includes "any_employee"
jsonpath "$.meta.resourceInstances['XX125'].actions['approve'].matchedPolicy" == "resource.leave_request.vdefault/acme.hr.uk"
jsonpath "$.meta.resourceInstances['XX125'].actions['delete'].matchedPolicy" == "resource.leave_request.vdefault/acme.hr.uk"
jsonpath "$.meta.resourceInstances['XX125'].actions['delete'].matchedScope" == "acme.hr.uk"
jsonpath "$.meta.resourceInstances['XX125'].actions['view:public'].matchedPolicy" == "resource.leave_request.vdefault/acme.hr.uk"
jsonpath "$.meta.resourceInstances['XX125'].actions['view:public'].matchedScope" == "acme.hr"


# Invalid CheckResourceSet request
POST {{protocol}}://{{host}}:{{port}}/api/check
Content-Type: application/json
file,requests/check_resource_set/bad_resource_set.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.resourceInstances[*]" count == 5
jsonpath "$.resourceInstances['XX125'].actions[*]" count == 4
jsonpath "$.resourceInstances['XX125'].actions['approve']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX125'].actions['create']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX125'].actions['defer']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX125'].actions['view:public']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX125'].validationErrors" count == 2
jsonpath "$.meta.resourceInstances['XX125'].actions['approve'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX125'].actions['create'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX125'].actions['defer'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX125'].actions['view:public'].matchedPolicy" == "resource.leave_request.v20210210"

jsonpath "$.resourceInstances['XX150'].actions[*]" count == 4
jsonpath "$.resourceInstances['XX150'].actions['approve']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX150'].actions['create']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX150'].actions['defer']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX150'].actions['view:public']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX150'].validationErrors" count == 2
jsonpath "$.meta.resourceInstances['XX150'].actions['approve'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX150'].actions['create'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX150'].actions['defer'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX150'].actions['view:public'].matchedPolicy" == "resource.leave_request.v20210210"

jsonpath "$.resourceInstances['XX250'].actions[*]" count == 4
jsonpath "$.resourceInstances['XX250'].actions['approve']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX250'].actions['create']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX250'].actions['defer']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX250'].actions['view:public']" == "EFFECT_DENY"
jsonpath "$.resourceInstances['XX250'].validationErrors" count == 2
jsonpath "$.meta.resourceInstances['XX250'].actions['approve'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX250'].actions['create'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX250'].actions['defer'].matchedPolicy" == "resource.leave_request.v20210210"
jsonpath "$.meta.resourceInstances['XX250'].actions['view:public'].matchedPolicy" == "resource.leave_request.v20210210"

jsonpath "$.resourceInstances['YY100'].actions[*]" count == 4
jsonpath "$.resourceInstances['YY100'].actions['approve']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY100'].actions['create']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY100'].actions['defer']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY100'].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.meta.resourceInstances['YY100'].actions['approve'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY100'].actions['create'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY100'].actions['defer'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY100'].actions['view:public'].matchedPolicy" == "principal.donald_duck.v20210210"

jsonpath "$.resourceInstances['YY200'].actions[*]" count == 4
jsonpath "$.resourceInstances['YY200'].actions['approve']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY200'].actions['create']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY200'].actions['defer']" == "EFFECT_ALLOW"
jsonpath "$.resourceInstances['YY200'].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.meta.resourceInstances['YY200'].actions['approve'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY200'].actions['create'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY200'].actions['defer'].matchedPolicy" == "principal.donald_duck.v20210210"
jsonpath "$.meta.resourceInstances['YY200'].actions['view:public'].matchedPolicy" == "principal.donald_duck.v20210210"


# Valid CheckResourceBatch request
POST {{protocol}}://{{host}}:{{port}}/api/check_resource_batch
Content-Type: application/json
file,requests/check_resource_batch/req01.json;
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

# Invalid CheckResourceBatch request
POST {{protocol}}://{{host}}:{{port}}/api/check_resource_batch
Content-Type: application/json
file,requests/check_resource_batch/bad_resource_batch.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.results" count == 2
jsonpath "$.results[?(@.resourceId == 'XX125')].actions[*]" count == 4
jsonpath "$.results[?(@.resourceId == 'XX125')].validationErrors" count == 2
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['approve']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['create']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['defer']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['view:public']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX150')].actions[*]" count == 3
jsonpath "$.results[?(@.resourceId == 'XX150')].validationErrors" count == 2
jsonpath "$.results[?(@.resourceId == 'XX150')].actions['approve']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX150')].actions['create']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX150')].actions['view:public']" == "EFFECT_DENY"


# Valid CheckResourceBatch request (scoped policies)
POST {{protocol}}://{{host}}:{{port}}/api/check_resource_batch
Content-Type: application/json
file,requests/check_resource_batch/req02.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.results" count == 2
jsonpath "$.results[?(@.resourceId == 'XX125')].actions[*]" count == 3
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['create']" == "EFFECT_ALLOW"
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['delete']" == "EFFECT_ALLOW"
jsonpath "$.results[?(@.resourceId == 'XX125')].actions['view:public']" == "EFFECT_ALLOW"
jsonpath "$.results[?(@.resourceId == 'XX225')].actions[*]" count == 3
jsonpath "$.results[?(@.resourceId == 'XX225')].actions['create']" == "EFFECT_ALLOW"
jsonpath "$.results[?(@.resourceId == 'XX225')].actions['delete']" == "EFFECT_DENY"
jsonpath "$.results[?(@.resourceId == 'XX225')].actions['view:public']" == "EFFECT_ALLOW"
