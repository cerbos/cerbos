---
apiVersion: api.cerbos.dev/v1
rolePolicy:
  role: admin
  scope: {{ .NameMod "tenant" }}
  parentRoles: ["admin"]
  rules:
    - resource: leave_request
      allowActions: ["create", "view", "approve", "delete"]
    - resource: salary_record
      allowActions: ["view", "edit", "delete"]
    - resource: expense_report
      allowActions: ["create", "view", "approve", "reject"]
    - resource: travel_booking
      allowActions: ["create", "view", "cancel", "approve"]
    - resource: equipment_request
      allowActions: ["create", "view", "approve", "fulfill"]
    - resource: project_assignment
      allowActions: ["create", "view", "reassign", "close"]
    - resource: performance_review
      allowActions: ["create", "view", "edit", "sign_off"]
    - resource: training_record
      allowActions: ["create", "view", "complete", "delete"]
    - resource: office_space
      allowActions: ["view", "reserve", "release", "assign"]
    - resource: document
      allowActions: ["create", "view", "edit", "delete", "share"]
    - resource: team_roster
      allowActions: ["view", "edit", "add_member", "remove_member"]
    - resource: budget_allocation
      allowActions: ["view", "propose", "approve", "revoke"]
