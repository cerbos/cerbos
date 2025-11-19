# Health endpoint should return 200 with SERVING in the body
GET {{protocol}}://{{host}}:{{port}}/_cerbos/health
HTTP 200
[Asserts]
body contains "SERVING"

# Metrics endpoint should return 200
GET {{protocol}}://{{host}}:{{port}}/_cerbos/metrics
HTTP 200

# Valid AccessEvaluationBatch request 1
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluations
Content-Type: application/json
file,requests/access_evaluation_batch/req01.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.evaluations" count == 7
jsonpath "$.evaluations[0].decision" == true
jsonpath "$.evaluations[1].decision" not exists
jsonpath "$.evaluations[2].decision" not exists
jsonpath "$.evaluations[3].decision" == true
jsonpath "$.evaluations[4].decision" == true
jsonpath "$.evaluations[5].decision" not exists
jsonpath "$.evaluations[6].decision" not exists

# Valid AccessEvaluationBatch request 2
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluations
Content-Type: application/json
file,requests/access_evaluation_batch/req02.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.evaluations" count == 6
jsonpath "$.evaluations[0].decision" == true
jsonpath "$.evaluations[1].decision" == true
jsonpath "$.evaluations[2].decision" == true
jsonpath "$.evaluations[3].decision" == true
jsonpath "$.evaluations[4].decision" not exists
jsonpath "$.evaluations[5].decision" == true

# Invalid AccessEvaluationBatch request 1
POST {{protocol}}://{{host}}:{{port}}/access/v1/evaluations
Content-Type: application/json
file,requests/access_evaluation_batch/bad_req01.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.evaluations" count == 7
jsonpath "$.evaluations[0].decision" not exists
jsonpath "$.evaluations[0].context['cerbos.response'].results[0].validationErrors[*]" count == 2
jsonpath "$.evaluations[1].decision" not exists
jsonpath "$.evaluations[1].context['cerbos.response'].results[0].validationErrors[*]" count == 2
jsonpath "$.evaluations[2].decision" not exists
jsonpath "$.evaluations[2].context['cerbos.response'].results[0].validationErrors[*]" count == 2
jsonpath "$.evaluations[3].decision" not exists
jsonpath "$.evaluations[3].context['cerbos.response'].results[0].validationErrors[*]" count == 2
jsonpath "$.evaluations[4].decision" not exists
jsonpath "$.evaluations[4].context['cerbos.response'].results[1].validationErrors[*]" count == 2
jsonpath "$.evaluations[5].decision" not exists
jsonpath "$.evaluations[5].context['cerbos.response'].results[1].validationErrors[*]" count == 2
jsonpath "$.evaluations[6].decision" not exists
jsonpath "$.evaluations[6].context['cerbos.response'].results[1].validationErrors[*]" count == 2
