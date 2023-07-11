# frozen_string_literal: true

require "cerbos"
require "json"

client = Cerbos::Client.new("localhost:3593", tls: false)

kind = "workspace"
actions = ["workspace:view", "pii:view"]

r1 = {
  kind: kind,
  id: "workspaceA"
}

r2 = {
  kind: kind,
  id: "workspaceB"
}

decision = client.check_resources(
  principal: {
    id: "123",
    roles: ["USER"],
    attributes: {
      workspaces: {
        workspaceA: {
          role: "OWNER"
        },
        workspaceB: {
          role: "MEMBER"
        }
      }
    }
  },
  resources: [
    {
      resource: r1,
      actions: actions
    },
    {
      resource: r2,
      actions: actions
    }
  ]
)

puts JSON.pretty_generate({
  results: [
    {
      resource: r1,
      actions: {
        "workspace:view": decision.allow?(resource: r1, action: "workspace:view"),
        "pii:view": decision.allow?(resource: r1, action: "pii:view")
      }
    },
    {
      resource: r2,
      actions: {
        "workspace:view": decision.allow?(resource: r2, action: "workspace:view"),
        "pii:view": decision.allow?(resource: r2, action: "pii:view")
      }
    }
  ]
})
