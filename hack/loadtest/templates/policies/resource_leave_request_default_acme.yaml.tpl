---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  resource: {{ .NameMod "leave_request" }}
  version: "default"
  scope: "acme"
  importDerivedRoles:
    - {{ .NameMod "alpha" }}
    - {{ .NameMod "beta" }}
  schemas:
    principalSchema:
      ref: "cerbos:///{{ .NameMod `principal` }}.json"
    resourceSchema:
      ref: "cerbos:///{{ .NameMod `leave_request` }}.json"
  rules:
    - actions: ["create"]
      derivedRoles:
        - employee_that_owns_the_record
      effect: EFFECT_ALLOW

    - actions: ["view:public"]
      derivedRoles:
        - any_employee
      effect: EFFECT_ALLOW
      name: public-view

