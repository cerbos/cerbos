require 'cerbos'
require 'json'

client = Cerbos::Client.new("localhost:3593", tls: false)

kind = "album:object"
actions = ["view:public", "comment"]

r1 = {
  :kind => kind,
  :id => "BUGS001",
  :attributes => {
    :owner => "bugs_bunny",
    :public => false,
    :flagged => false,
  }
}

r2 = {
  :kind => kind,
  :id => "DAFFY002",
  :attributes => {
    :owner => "daffy_duck",
    :public => true,
    :flagged => false,
  }
}

decision = client.check_resources(
  principal: {
    id: "bugs_bunny",
    roles: ["user"],
    attributes: {
      beta_tester: true,
    },
  },
  resources: [
    {
      resource: r1,
      actions: actions
    },
    {
      resource: r2,
      actions: actions
    },
  ],
)

res = {
  :results => [
    {
      :resource => r1,
      :actions => {
        :comment => decision.allow?(resource: r1, action: "comment"),
        :"view:public" => decision.allow?(resource: r1, action: "view:public"),
      },
    },
    {
      :resource => r2,
      :actions => {
        :comment => decision.allow?(resource: r2, action: "comment"),
        :"view:public" => decision.allow?(resource: r2, action: "view:public"),
      },
    },
  ],
}
puts JSON.pretty_generate(res)
