---
apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: admin
  scope: {{ .NameMod "tenant" }}.hr
  parentRoles: ["admin"]
  rules:
    - resource: leave_request
      allowActions: ["create", "view", "approve", "delete"]
    - resource: salary_record
      allowActions: ["view", "edit"]
    - resource: expense_report
      allowActions: ["create", "view", "approve"]
    - resource: performance_review
      allowActions: ["create", "view", "edit", "sign_off"]
    - resource: training_record
      allowActions: ["create", "view", "complete"]
    - resource: document
      allowActions: ["create", "view", "edit", "share"]
    - resource: team_roster
      allowActions: ["view", "edit", "add_member", "remove_member"]
