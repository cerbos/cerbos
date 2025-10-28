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
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req01_XX125_approve (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX125_approve.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req01_XX125_create (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX125_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req01_XX125_defer (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX125_defer.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req01_XX150_view_public (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX150_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req01_XX150_approve (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX150_approve.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req01_XX150_create (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req01_XX150_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req02_XX125_view_public (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX125_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req02_XX125_delete (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX125_delete.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req02_XX125_create (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX125_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req02_XX225_view_public (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX225_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req02_XX225_delete (expect DENY)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX225_delete.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Valid AccessEvaluation request - req02_XX225_create (expect ALLOW)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/req02_XX225_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" == true
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Invalid AccessEvaluation request - bad_req01_XX125_view_public (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX125_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Invalid AccessEvaluation request - bad_req01_XX125_approve (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX125_approve.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Invalid AccessEvaluation request - bad_req01_XX125_create (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX125_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Invalid AccessEvaluation request - bad_req01_XX125_defer (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX125_defer.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Invalid AccessEvaluation request - bad_req01_XX150_view_public (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX150_view_public.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Invalid AccessEvaluation request - bad_req01_XX150_approve (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX150_approve.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists

# Invalid AccessEvaluation request - bad_req01_XX150_create (expect DENY with validation errors)
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluation
Content-Type: application/json
file,requests/access_evaluation/bad_req01_XX150_create.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.decision" not exists
jsonpath "$.context.id" == "test"
jsonpath "$.context.reasonUser.properties['cerbos.response']" exists