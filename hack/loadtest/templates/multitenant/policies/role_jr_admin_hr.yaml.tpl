---
apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: jr_admin
  scope: {{ .NameMod "tenant" }}.hr
  parentRoles: ["admin"]
  rules:
    - resource: leave_request
      allowActions: ["create", "view"]
    - resource: salary_record
      allowActions: ["view"]
      condition:
        match:
          expr: P.attr.department == R.attr.department
    - resource: expense_report
      allowActions: ["view"]
    - resource: performance_review
      allowActions: ["view"]
    - resource: training_record
      allowActions: ["view"]
    - resource: document
      allowActions: ["create", "view"]
    - resource: team_roster
      allowActions: ["view"]
