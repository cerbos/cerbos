---
apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: admin
  scope: {{ .NameMod "tenant" }}.hr.uk
  parentRoles: ["admin"]
  rules:
    - resource: leave_request
      allowActions: ["create", "view", "approve"]
      condition:
        match:
          expr: P.attr.department == "hr"
    - resource: salary_record
      allowActions: ["view"]
      condition:
        match:
          expr: P.attr.clearance_level >= 3
    - resource: expense_report
      allowActions: ["view", "approve"]
    - resource: document
      allowActions: ["create", "view", "edit"]
    - resource: team_roster
      allowActions: ["view"]
