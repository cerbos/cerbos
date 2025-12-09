# Health endpoint should return 200 with SERVING in the body
GET {{protocol}}://{{host}}:{{port}}/_cerbos/health
HTTP 200
[Asserts]
body contains "SERVING"

# Metrics endpoint should return 200
GET {{protocol}}://{{host}}:{{port}}/_cerbos/metrics
HTTP 200

# Valid AccessEvaluation request - req01_XX125_view_public (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX125_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['view:public']" == "EFFECT_ALLOW"

# Valid AccessEvaluation request - req01_XX125_approve (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX125_approve.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['approve']" == "EFFECT_DENY"

# Valid AccessEvaluation request - req01_XX125_create (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX125_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['create']" == "EFFECT_DENY"

# Valid AccessEvaluation request - req01_XX125_defer (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX125_defer.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['defer']" == "EFFECT_ALLOW"

# Valid AccessEvaluation request - req01_XX150_view_public (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX150_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX150"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['view:public']" == "EFFECT_ALLOW"

# Valid AccessEvaluation request - req01_XX150_approve (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX150_approve.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX150"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['approve']" == "EFFECT_DENY"

# Valid AccessEvaluation request - req01_XX150_create (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX150_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX150"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['create']" == "EFFECT_DENY"

# Valid AccessEvaluation request - req02_XX125_view_public (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX125_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].resource.scope" == "acme.hr.uk"
jsonpath "$.context['cerbos.response'].results[0].actions['view:public']" == "EFFECT_ALLOW"

# Valid AccessEvaluation request - req02_XX125_delete (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX125_delete.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].resource.scope" == "acme.hr.uk"
jsonpath "$.context['cerbos.response'].results[0].actions['delete']" == "EFFECT_ALLOW"

# Valid AccessEvaluation request - req02_XX125_create (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX125_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].resource.scope" == "acme.hr.uk"
jsonpath "$.context['cerbos.response'].results[0].actions['create']" == "EFFECT_ALLOW"

# Valid AccessEvaluation request - req02_XX225_view_public (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX225_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX225"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].resource.scope" == "acme.hr"
jsonpath "$.context['cerbos.response'].results[0].actions['view:public']" == "EFFECT_ALLOW"

# Valid AccessEvaluation request - req02_XX225_delete (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX225_delete.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX225"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].resource.scope" == "acme.hr"
jsonpath "$.context['cerbos.response'].results[0].actions['delete']" == "EFFECT_DENY"

# Valid AccessEvaluation request - req02_XX225_create (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX225_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX225"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].resource.scope" == "acme.hr"
jsonpath "$.context['cerbos.response'].results[0].actions['create']" == "EFFECT_ALLOW"

# Invalid AccessEvaluation request - bad_req01_XX125_view_public (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX125_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['view:public']" == "EFFECT_DENY"
jsonpath "$.context['cerbos.response'].results[0].validationErrors[*]" count == 2

# Invalid AccessEvaluation request - bad_req01_XX125_approve (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX125_approve.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['approve']" == "EFFECT_DENY"
jsonpath "$.context['cerbos.response'].results[0].validationErrors[*]" count == 2

# Invalid AccessEvaluation request - bad_req01_XX125_create (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX125_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['create']" == "EFFECT_DENY"
jsonpath "$.context['cerbos.response'].results[0].validationErrors[*]" count == 2

# Invalid AccessEvaluation request - bad_req01_XX125_defer (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX125_defer.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['defer']" == "EFFECT_DENY"
jsonpath "$.context['cerbos.response'].results[0].validationErrors[*]" count == 2

# Invalid AccessEvaluation request - bad_req01_XX150_view_public (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX150_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX150"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['view:public']" == "EFFECT_DENY"
jsonpath "$.context['cerbos.response'].results[0].validationErrors[*]" count == 2

# Invalid AccessEvaluation request - bad_req01_XX150_approve (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX150_approve.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX150"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['approve']" == "EFFECT_DENY"
jsonpath "$.context['cerbos.response'].results[0].validationErrors[*]" count == 2

# Invalid AccessEvaluation request - bad_req01_XX150_create (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX150_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == false
jsonpath "$.context['cerbos.response'].requestId" == "test"
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX150"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "leave_request"
jsonpath "$.context['cerbos.response'].results[0].actions['create']" == "EFFECT_DENY"
jsonpath "$.context['cerbos.response'].results[0].validationErrors[*]" count == 2

# Valid AccessEvaluation request - req03_XX125_view_public.json (plain output)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req03_XX125_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context['cerbos.response'].results" count == 1
jsonpath "$.context['cerbos.response'].results[0].resource.id" == "XX125"
jsonpath "$.context['cerbos.response'].results[0].resource.kind" == "equipment_request"
jsonpath "$.context['cerbos.response'].results[0].outputs[0].val.id" == "employee1"
