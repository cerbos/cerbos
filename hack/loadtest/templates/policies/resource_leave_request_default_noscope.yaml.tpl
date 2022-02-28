---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  resource: {{ .NameMod "leave_request" }}
  version: "default"
  importDerivedRoles:
    - {{ .NameMod "alpha" }}
    - {{ .NameMod "beta" }}
  schemas:
    principalSchema:
      ref: "cerbos:///{{ .NameMod `principal` }}.json"
    resourceSchema:
      ref: "cerbos:///{{ .NameMod `leave_request` }}.json"
  rules:
    - actions: ['*']
      effect: EFFECT_ALLOW
      roles:
        - admin
      name: wildcard
