{
  "url": "/api/check/resources",
  "request": {
    "requestId": "{{ .RequestID }}",
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
    "resources": [
      {
        "actions": [
          "view:public",
          "approve"
        ],
        "resource": {
          "kind": "{{ .NameMod `leave_request` }}",
          "policyVersion": "20210210",
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
          "approve"
        ],
        "resource": {
          "kind": "{{ .NameMod `leave_request` }}",
          "policyVersion": "20210210",
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
          "approve"
        ],
        "resource": {
          "kind": "{{ .NameMod `leave_request` }}",
          "policyVersion": "20210210",
          "id": "ZZ125",
          "attr": {
            "department": "finance",
            "geography": "GB",
            "id": "ZZ125",
            "owner": "dani",
            "team": "accounting"
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
          "policyVersion": "20210210",
          "id": "AA125",
          "attr": {
            "department": "finance",
            "geography": "GB",
            "id": "AA125",
            "owner": "robert",
            "team": "accounting"
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
          "policyVersion": "20210210",
          "id": "BB125",
          "attr": {
            "department": "engineering",
            "geography": "US",
            "id": "BB125",
            "owner": "anya",
            "team": "sre"
          }
        }
      }
    ]
  },
  "wantResponse": {
    "requestId": "{{ .RequestID }}",
    "results": [
      {
        "resource": {
            "id": "XX125",
            "kind": "{{ .NameMod `leave_request` }}",
            "policyVersion": "20210210"
        },
        "actions": {
          "view:public": "EFFECT_ALLOW",
          "approve": "EFFECT_DENY"
        }
      },
      {
        "resource": {
            "id": "YY125",
            "kind": "{{ .NameMod `leave_request` }}",
            "policyVersion": "20210210"
        },
        "actions": {
          "view:public": "EFFECT_ALLOW",
          "approve": "EFFECT_DENY"
        }
      },
      {
        "resource": {
            "id": "ZZ125",
            "kind": "{{ .NameMod `leave_request` }}",
            "policyVersion": "20210210"
        },
        "actions": {
          "view:public": "EFFECT_ALLOW",
          "approve": "EFFECT_DENY"
        }
      },
      {
        "resource": {
            "id": "AA125",
            "kind": "{{ .NameMod `leave_request` }}",
            "policyVersion": "20210210"
        },
        "actions": {
          "view:public": "EFFECT_ALLOW",
          "approve": "EFFECT_DENY"
        }
      },
      {
        "resource": {
            "id": "BB125",
            "kind": "{{ .NameMod `leave_request` }}",
            "policyVersion": "20210210"
        },
        "actions": {
          "view:public": "EFFECT_ALLOW",
          "approve": "EFFECT_DENY"
        }
      }
    ]
  }
}
