# Playground validate request 1
POST {{protocol}}://{{host}}:{{port}}/api/playground/validate
Content-Type: application/json
file,requests/playground_validate/req1.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.success" != null


# Playground validate request 2
POST {{protocol}}://{{host}}:{{port}}/api/playground/validate
Content-Type: application/json
file,requests/playground_validate/req2.json;
HTTP/* 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.failure.errors" count == 1
jsonpath "$.failure.errors[0].file" == "resource.yaml"
jsonpath "$.failure.errors[0].error" == "Import 'apatr_common_roles' not found"


# Playground validate request 3
POST {{protocol}}://{{host}}:{{port}}/api/playground/validate
Content-Type: application/json
file,requests/playground_validate/req3.json;
HTTP/* 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.failure.errors" count == 2
jsonpath "$.failure.errors[?(@.file == 'resource.yaml')].error" == "Import 'apatr_common_roles' not found"
jsonpath "$.failure.errors[?(@.file == 'common_roles.yaml')].error" == "Failed to read: invalid Policy.PolicyType: value is required"


# Playground evaluate request 1
POST {{protocol}}://{{host}}:{{port}}/api/playground/evaluate
Content-Type: application/json
file,requests/playground_evaluate/req1.json;
HTTP/* 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.success.results" count == 2
jsonpath "$.success.results[0].action" == "view"
jsonpath "$.success.results[0].effect" == "EFFECT_ALLOW"
jsonpath "$.success.results[0].policy" == "resource.album_object.vdefault"
jsonpath "$.success.results[0].effectiveDerivedRoles" count == 1 
jsonpath "$.success.results[0].effectiveDerivedRoles[0]" == "owner" 

jsonpath "$.success.results[1].action" == "delete"
jsonpath "$.success.results[1].effect" == "EFFECT_ALLOW"
jsonpath "$.success.results[1].policy" == "resource.album_object.vdefault"
jsonpath "$.success.results[1].effectiveDerivedRoles" count == 1 
jsonpath "$.success.results[1].effectiveDerivedRoles[0]" == "owner" 


# Playground evaluate request 2
POST {{protocol}}://{{host}}:{{port}}/api/playground/evaluate
Content-Type: application/json
file,requests/playground_evaluate/req2.json;
HTTP/* 400
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.failure.errors" count == 1
jsonpath "$.failure.errors[0].file" == "resource.yaml"
jsonpath "$.failure.errors[0].error" == "Import 'apatr_common_roles' not found"
