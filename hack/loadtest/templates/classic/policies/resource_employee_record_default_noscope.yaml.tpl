---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  resource: {{ .NameMod "employee_record" }}
  version: "default"
  importDerivedRoles:
    - {{ .NameMod "alpha" }}
    - {{ .NameMod "beta" }}
  schemas:
    principalSchema:
      ref: "cerbos:///{{ .NameMod `principal` }}.json"
    resourceSchema:
      ref: "cerbos:///{{ .NameMod `employee_record` }}.json"
  rules:
    - actions: ['*']
      effect: EFFECT_ALLOW
      roles:
        - admin
      name: wildcard
