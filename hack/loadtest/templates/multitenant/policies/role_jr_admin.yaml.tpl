---
apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: jr_admin
  scope: {{ .NameMod "tenant" }}
  parentRoles: ["admin"]
  rules:
    - resource: leave_request
      allowActions: ["create", "view", "approve"]
    - resource: salary_record
      allowActions: ["view"]
    - resource: expense_report
      allowActions: ["create", "view"]
    - resource: travel_booking
      allowActions: ["create", "view"]
    - resource: equipment_request
      allowActions: ["create", "view"]
    - resource: project_assignment
      allowActions: ["view"]
    - resource: performance_review
      allowActions: ["view", "edit"]
    - resource: training_record
      allowActions: ["create", "view"]
    - resource: office_space
      allowActions: ["view", "reserve"]
    - resource: document
      allowActions: ["create", "view", "edit"]
    - resource: team_roster
      allowActions: ["view"]
    - resource: budget_allocation
      allowActions: ["view"]
