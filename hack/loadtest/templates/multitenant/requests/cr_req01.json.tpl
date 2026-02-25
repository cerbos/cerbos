{
  "requestId": "{{ .RequestID }}",
  "principal": {
    "id": "admin_user_01",
    "scope": "{{ .NameMod "tenant" }}.hr.uk",
    "roles": [
      "admin"
    ],
    "attr": {
      "tenantId": "{{ .NameMod "tenant" }}",
      "department": "hr",
      "clearance_level": 5
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
        "scope": "{{ .NameMod "tenant" }}.hr.uk",
        "id": "LR001",
        "attr": {
          "tenantId": "{{ .NameMod "tenant" }}",
          "department": "hr",
          "owner": "emp_42"
        }
      }
    },
    {
      "actions": [
        "view",
        "edit"
      ],
      "resource": {
        "kind": "salary_record",
        "scope": "{{ .NameMod "tenant" }}.hr.uk",
        "id": "SR001",
        "attr": {
          "tenantId": "{{ .NameMod "tenant" }}",
          "department": "hr",
          "owner": "emp_42"
        }
      }
    },
    {
      "actions": [
        "view",
        "approve"
      ],
      "resource": {
        "kind": "expense_report",
        "scope": "{{ .NameMod "tenant" }}.hr.uk",
        "id": "ER001",
        "attr": {
          "tenantId": "{{ .NameMod "tenant" }}",
          "department": "hr",
          "owner": "emp_55"
        }
      }
    },
    {
      "actions": [
        "create",
        "view",
        "edit"
      ],
      "resource": {
        "kind": "document",
        "scope": "{{ .NameMod "tenant" }}.hr.uk",
        "id": "DOC001",
        "attr": {
          "tenantId": "{{ .NameMod "tenant" }}",
          "department": "hr",
          "owner": "admin_user_01"
        }
      }
    }
  ]
}
