A typical request should be structured as follows:

```json
{
  "action": "view:public",
  "resource": {
    "type": "leave_request",
    "id": "XX12345",
    "version": "v1",
    "attr": {
      "owner": "john",
      "geography": "GB",
      "department": "marketing",
      "team": "design",
      "status": "APPROVED",
      "upcoming_request": true,
    }
  },
  "principal": {
    "id": "john",
    "roles": ["employee"],
    "attr": {
      "geography": "GB",
      "department": "marketing",
      "team": "design"
    }
  }
}
```

`attr` is a bag of values to provide contextual information about the request. The provided values will be used to compute “ComputedRoles” and `conditions`. 

Computed roles are defined as follows: 

```yaml
apiVersion: paams.dev/v1
kind: ComputedRoles
name: my_computed_roles
definitions:
  - name: admin
    parentRoles: ["admin"]

  - name: employee_that_owns_the_record
    parentRoles: ["employee"]
    # Computation done by a Rego script. For advanced users.
    computation:
      script: |-
        input.resource.attr.owner == input.principal.id

  - name: any_employee
    parentRoles: ["employee"]

  - name: direct_manager
    parentRoles: ["manager"]
    # Computation done by “pscript” — a simplified Rego for expressing common concepts like comparisons and set membership.  
    computation:
      match:
        expr:
          - "$resource.attr.geography == $principal.attr.geography"
          - "$resource.attr.geography == $principal.attr.managed_geographies"
```

A policy is defined per resource in the system.

```yaml
---
apiVersion: paams.dev/v1
kind: ResourcePolicy
name: my_policy
# Resource this policy applies to.
resource: leave_request
# Resource version. The combination of resource and resource version must be unique. Useful for system migrations and/or testing before rolling out.
resourceVersion: v1
# Import the computed role definitions as they can be shared between different resources
requiredComputedRoles:
    - my_computed_roles
rules:
  - action: *
    computedRoles:
     - admin
    effect: EFFECT_ALLOW

  - action: create
    computedRoles:
      - employee_that_owns_the_record
    effect: EFFECT_ALLOW

  - action: view:*
    computedRoles:
      - employee_that_owns_the_record
      - direct_manager
    effect: EFFECT_ALLOW

  - action: approve
    computedRoles:
      - direct_manager
    condition:
      match:
        expr:
          - "$resource.attr.status == PENDING_APPROVAL"
    effect: EFFECT_ALLOW

# Overrides for certain individuals
overrides:
  - action: * 
    when:
      expr:
        - "$principal.id == emre"
    effect: EFFECT_ALLOW
```
