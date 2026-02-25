{
  "requestId": "{{ .RequestID }}",
  "principal": {
    "id": "assistant_user_01",
    "scope": "{{ .NameMod "tenant" }}.hr",
    "roles": [
      "assistant"
    ],
    "attr": {
      "tenantId": "{{ .NameMod "tenant" }}",
      "department": "hr",
      "clearance_level": 1
    }
  },
  "resources": [
    {
      "actions": [
        "create",
        "view",
        "approve"
      ],
      "resource": {
        "kind": "leave_request",
        "scope": "{{ .NameMod "tenant" }}.hr",
        "id": "LR002",
        "attr": {
          "tenantId": "{{ .NameMod "tenant" }}",
          "department": "hr",
          "owner": "emp_77"
        }
      }
    },
    {
      "actions": [
        "view",
        "edit",
        "share"
      ],
      "resource": {
        "kind": "document",
        "scope": "{{ .NameMod "tenant" }}.hr",
        "id": "DOC002",
        "attr": {
          "tenantId": "{{ .NameMod "tenant" }}",
          "department": "hr",
          "owner": "emp_88"
        }
      }
    }
  ]
}
