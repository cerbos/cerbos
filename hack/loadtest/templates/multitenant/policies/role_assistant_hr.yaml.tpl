---
apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: assistant
  scope: {{ .NameMod "tenant" }}.hr
  parentRoles: ["jr_admin"]
  rules:
    - resource: leave_request
      allowActions: ["create", "view"]
      condition:
        match:
          expr: P.attr.department == R.attr.department
    - resource: document
      allowActions: ["view"]
    - resource: training_record
      allowActions: ["view"]
