---
apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: manager
  scope: {{ .NameMod "tenant" }}
  parentRoles: ["manager"]
  rules:
    - resource: leave_request
      allowActions: ["view", "approve"]
    - resource: expense_report
      allowActions: ["view", "approve"]
    - resource: travel_booking
      allowActions: ["view", "approve"]
    - resource: project_assignment
      allowActions: ["create", "view", "reassign"]
    - resource: performance_review
      allowActions: ["create", "view", "edit", "sign_off"]
    - resource: team_roster
      allowActions: ["view", "edit", "add_member", "remove_member"]
    - resource: document
      allowActions: ["create", "view", "edit"]
    - resource: budget_allocation
      allowActions: ["view", "propose"]
