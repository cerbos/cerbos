---
apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: manager
  scope: {{ .NameMod "tenant" }}.hr
  parentRoles: ["manager"]
  rules:
    - resource: leave_request
      allowActions: ["view", "approve"]
      condition:
        match:
          expr: P.attr.department == R.attr.department
    - resource: expense_report
      allowActions: ["view"]
    - resource: performance_review
      allowActions: ["view", "edit"]
    - resource: document
      allowActions: ["view", "edit"]
    - resource: team_roster
      allowActions: ["view"]
