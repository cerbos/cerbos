# Admin AddOrUpdatePolicy
POST {{protocol}}://{{host}}:{{port}}/admin/policy
Content-Type: application/json
file,requests/admin_add_or_update_policy/req01.json;
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.success" != null
