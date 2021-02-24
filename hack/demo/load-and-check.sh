#!/usr/bin/env bash

set -euo pipefail

SERVER=http://localhost:9999
CHECK_URL="${SERVER}/v1/check"
POLICY_URL="${SERVER}/v1/admin/policy"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
    echo ""
    echo ""
    echo -e "\e[31m==================================\e[0m"
    echo -e "\e[31m$1\e[0m"
    echo -e "\e[31m==================================\e[0m"
}

log "Adding derived roles"
cat <<"EOF" | curl -i -XPUT "$POLICY_URL" --data-binary @-
---
apiVersion: "paams.dev/v1"
derived_roles:
  name: my_derived_roles
  definitions:
    - name: admin
      parentRoles: ["admin"]

    - name: tester
      parentRoles: ["dev", "qa"]

    - name: employee_that_owns_the_record
      parentRoles: ["employee"]
      computation:
        script: |-
          input.resource.attr.owner == input.principal.id

    - name: any_employee
      parentRoles: ["employee"]

    - name: direct_manager
      parentRoles: ["manager"]
      computation:
        match:
          expr:
            - "$resource.attr.geography == $principal.attr.geography"
            - "$resource.attr.geography == $principal.attr.managed_geographies"
EOF


log "Adding resource policy"
cat <<"EOF" | curl -i -XPUT "$POLICY_URL" --data-binary @-
---
apiVersion: paams.dev/v1
resourcePolicy:
  importDerivedRoles:
  - my_derived_roles
  resource: leave_request
  rules:
  - action: '*'
    effect: EFFECT_ALLOW
    roles:
    - admin
  - action: create
    derivedRoles:
    - employee_that_owns_the_record
    effect: EFFECT_ALLOW
  - action: view:*
    derivedRoles:
    - employee_that_owns_the_record
    - direct_manager
    effect: EFFECT_ALLOW
  - action: view:public
    derivedRoles:
    - any_employee
    effect: EFFECT_ALLOW
  - action: approve
    condition:
      match:
        expr:
        - $resource.attr.status == "PENDING_APPROVAL"
    derivedRoles:
    - direct_manager
    effect: EFFECT_ALLOW
  version: "20210210"
EOF

log "Adding principal policy"
cat <<"EOF" | curl -i -XPUT "$POLICY_URL" --data-binary @-
---
apiVersion: "paams.dev/v1"
principalPolicy:
  principal: donald_duck
  version: "20210210"
  rules:
    - resource: leave_request
      actions:
        - action: "*"
          condition:
            match:
              expr:
                - "$resource.attr.dev_record == true"
          effect: EFFECT_ALLOW

    - resource: salary_record
      actions:
        - action: "*"
          effect: EFFECT_DENY
EOF

log "[CHECK] Employee viewing his own leave_request"
cat <<EOF | curl -i "$CHECK_URL" -d @- 
{
  "requestId":  "test01",
  "resource":  {
    "name":  "leave_request",
    "version":  "20210210",
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "john",
    "version":  "20210210",
    "roles":  [
      "employee"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "team":  "design"
    }
  },
  "action":  "view:public"
}
EOF

log "[CHECK] Employee approving his own leave_request"
cat <<EOF | curl -i "$CHECK_URL" -d @- 
{
  "requestId":  "test02",
  "resource":  {
    "name":  "leave_request",
    "version":  "20210210",
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "john",
    "version":  "20210210",
    "roles":  [
      "employee"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "team":  "design"
    }
  },
  "action":  "approve"
}
EOF


log "[CHECK] Direct manager approving leave_request"
cat <<EOF | curl -i "$CHECK_URL" -d @- 
{
  "requestId":  "test03",
  "resource":  {
    "name":  "leave_request",
    "version":  "20210210",
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "status":  "PENDING_APPROVAL",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "sally",
    "version":  "20210210",
    "roles":  [
      "employee",
      "manager"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "managed_geographies":  "GB",
      "team":  "design"
    }
  },
  "action":  "approve"
}
EOF

log "[CHECK] Manager from different geography approving leave_request"
cat <<EOF | curl -i "$CHECK_URL" -d @- 
{
  "requestId":  "test04",
  "resource":  {
    "name":  "leave_request",
    "version":  "20210210",
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "status":  "PENDING_APPROVAL",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "betty",
    "version":  "20210210",
    "roles":  [
      "employee",
      "manager"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "managed_geographies":  "FR",
      "team":  "design"
    }
  },
  "action":  "approve"
}
EOF


log "[CHECK] [Override for specific user] Donald Duck approving leave_request"
cat <<EOF | curl -i "$CHECK_URL" -d @- 
{
  "requestId":  "test05",
  "resource":  {
    "name":  "leave_request",
    "version":  "20210210",
    "attr":  {
      "department":  "marketing",
      "dev_record":  true,
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "donald_duck",
    "version":  "20210210",
    "roles":  [
      "employee"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "team":  "design"
    }
  },
  "action":  "approve"
}
EOF


log "[CHECK] [Override for specific user] Donald Duck viewing salary record"
cat <<EOF | curl -i "$CHECK_URL" -d @- 
{
  "requestId":  "test06",
  "resource":  {
    "name":  "salary_record",
    "version":  "20210210",
    "attr":  {
      "department":  "marketing",
      "dev_record":  true,
      "geography":  "GB",
      "id":  "XX125",
      "owner":  "john",
      "team":  "design"
    }
  },
  "principal":  {
    "id":  "donald_duck",
    "version":  "20210210",
    "roles":  [
      "employee"
    ],
    "attr":  {
      "department":  "marketing",
      "geography":  "GB",
      "team":  "design"
    }
  },
  "action":  "view"
}
EOF
