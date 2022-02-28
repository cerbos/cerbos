{
  "url": "/api/check",
  "request": {
    "requestId": "{{ .RequestID }}",
    "actions": [
      "view:public",
      "delete",
      "approve"
    ],
    "principal": {
      "id": "john",
      "roles": [
        "employee"
      ],
      "attr": {
        "department": "marketing",
        "geography": "GB",
        "team": "design",
        "ip_address": "10.20.0.5"
      }
    },
    "resource": {
      "kind": "{{ .NameMod `leave_request` }}",
      "scope": "acme.hr.uk",
      "instances": {
        "XX125": {
          "attr": {
            "department": "marketing",
            "geography": "GB",
            "id": "XX125",
            "owner": "john",
            "team": "design"
          }
        }
      }
    }
  },
  "wantResponse": {
    "requestId": "{{ .RequestID }}",
    "resourceInstances": {
      "XX125": {
        "actions": {
          "view:public": "EFFECT_ALLOW",
          "delete": "EFFECT_ALLOW",
          "approve": "EFFECT_DENY"
        }
      }
    }
  }
}
