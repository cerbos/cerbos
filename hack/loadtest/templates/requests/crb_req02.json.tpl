{
  "url": "/api/check_resource_batch",
  "request": {
    "requestId": "{{ .RequestID }}",
    "principal": {
      "id": "john",
      "scope": "acme.hr",
      "roles": [
        "employee"
      ],
      "attr": {
        "department": "marketing",
        "geography": "GB",
        "team": "design",
        "ip_address": "10.20.5.5"
      }
    },
    "resources": [
      {
        "actions": [
          "view:public",
          "delete",
          "create"
        ],
        "resource": {
          "kind": "{{ .NameMod `leave_request` }}",
          "scope": "acme.hr.uk",
          "id": "XX125",
          "attr": {
            "department": "marketing",
            "geography": "GB",
            "id": "XX125",
            "owner": "john",
            "team": "design"
          }
        }
      },
      {
        "actions": [
          "view:public",
          "delete",
          "create"
        ],
        "resource": {
          "kind": "{{ .NameMod `leave_request` }}",
          "scope": "acme.hr",
          "id": "XX225",
          "attr": {
            "department": "marketing",
            "geography": "GB",
            "id": "XX225",
            "owner": "john",
            "team": "design"
          }
        }
      },
      {
        "actions": [
          "view:public",
          "approve"
        ],
        "resource": {
          "kind": "{{ .NameMod `leave_request` }}",
          "scope": "acme.hr.uk",
          "id": "YY125",
          "attr": {
            "department": "engineering",
            "geography": "GB",
            "id": "YY125",
            "owner": "jenny",
            "team": "backend"
          }
        }
      },
      {
        "actions": [
          "view:public",
          "delete",
          "edit"
        ],
        "resource": {
          "kind": "{{ .NameMod `salary_record` }}",
          "policyVersion": "20210210",
          "id": "YY525",
          "attr": {
            "department": "engineering",
            "geography": "GB",
            "id": "YY525",
            "owner": "mark",
            "team": "backend"
          }
        }
      }
    ]
  },
  "wantResponse": {
    "requestId": "{{ .RequestID }}",
    "results": [
      {
        "resourceId": "XX125",
        "actions": {
          "view:public": "EFFECT_ALLOW",
          "delete": "EFFECT_ALLOW",
          "create": "EFFECT_ALLOW"
        }
      },
      {
        "resourceId": "XX225",
        "actions": {
          "view:public": "EFFECT_ALLOW",
          "delete": "EFFECT_DENY",
          "create": "EFFECT_ALLOW"
        }
      },
      {
        "resourceId": "YY125",
        "actions": {
          "view:public": "EFFECT_ALLOW",
          "approve": "EFFECT_DENY"
        }
      },
      {
        "resourceId": "YY525",
        "actions": {
          "view:public": "EFFECT_DENY",
          "delete": "EFFECT_DENY",
          "edit": "EFFECT_DENY"
        }
      }
    ]
  }
}
