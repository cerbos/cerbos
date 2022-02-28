{
  "url": "/api/check",
  "request": {
    "requestId": "{{ .RequestID }}",
    "actions": [
      "view:public",
      "approve"
    ],
    "principal": {
      "id": "john",
      "policyVersion": "20210210",
      "roles": [
        "employee"
      ],
      "attr": {
        "department": "marketing",
        "geography": "GB",
        "team": "design"
      }
    },
    "resource": {
      "kind": "{{ .NameMod `leave_request` }}",
      "policyVersion": "20210210",
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
          "approve": "EFFECT_DENY"
        }
      }
    }
  }
}
