# Playground validate request 1
POST {{protocol}}://{{host}}:{{port}}/api/playground/validate
Content-Type: application/json
file,requests/playground_validate/req1.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.success" != null


# Playground validate request 2
POST {{protocol}}://{{host}}:{{port}}/api/playground/validate
Content-Type: application/json
file,requests/playground_validate/req2.json;
HTTP 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.failure.errors" count == 1
jsonpath "$.failure.errors[0].file" == "resource.yaml"
jsonpath "$.failure.errors[0].error" == "cannot find derived roles 'apatr_common_roles' imported by policy resource.album_object.vdefault"


# Playground validate request 3
POST {{protocol}}://{{host}}:{{port}}/api/playground/validate
Content-Type: application/json
file,requests/playground_validate/req3.json;
HTTP 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.failure.errors" count == 2
jsonpath "$.failure.errors[?(@.file == 'resource.yaml')].error" nth 0 == "cannot find derived roles 'apatr_common_roles' imported by policy resource.album_object.vdefault"
jsonpath "$.failure.errors[?(@.file == 'common_roles.yaml')].error" nth 0 == "Failed to read: policyType: exactly one field is required in oneof"


# Playground evaluate request 1
POST {{protocol}}://{{host}}:{{port}}/api/playground/evaluate
Content-Type: application/json
file,requests/playground_evaluate/req1.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.success.results" count == 2
jsonpath "$.success.results[?(@.action == 'view')].effect" nth 0 == "EFFECT_ALLOW"
jsonpath "$.success.results[?(@.action == 'view')].policy" nth 0 == "resource.album_object.vdefault"
jsonpath "$.success.effectiveDerivedRoles" count == 1
jsonpath "$.success.effectiveDerivedRoles[0]" == "owner"

jsonpath "$.success.results[?(@.action == 'delete')].effect" nth 0 == "EFFECT_ALLOW"
jsonpath "$.success.results[?(@.action == 'delete')].policy" nth 0 == "resource.album_object.vdefault"
jsonpath "$.success.effectiveDerivedRoles" count == 1
jsonpath "$.success.effectiveDerivedRoles[0]" == "owner"


# Playground evaluate request 2
POST {{protocol}}://{{host}}:{{port}}/api/playground/evaluate
Content-Type: application/json
file,requests/playground_evaluate/req2.json;
HTTP 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.failure.errors" count == 1
jsonpath "$.failure.errors[0].file" == "resource.yaml"
jsonpath "$.failure.errors[0].error" == "cannot find derived roles 'apatr_common_roles' imported by policy resource.album_object.vdefault"
