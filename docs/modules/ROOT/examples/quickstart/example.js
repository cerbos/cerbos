const { GRPC: Cerbos } = require("@cerbos/grpc");

const cerbos = new Cerbos("localhost:3593", { tls: false });

(async() => {
  const kind = "album:object";
  const actions = ["view:public", "comment"];

  const cerbosPayload = {
    principal: {
      id: "bugs_bunny",
      roles: ["user"],
      attributes: {
        beta_tester: true,
      },
    },
    resources: [
      {
        resource: {
          kind: kind,
          id: "BUGS001",
          attributes: {
		    owner:   "bugs_bunny",
		    public:  false,
		    flagged: false,
          },
        },
        actions: actions,
      },
      {
        resource: {
          kind: kind,
          id: "DAFFY002",
          attributes: {
		    owner:   "daffy_duck",
		    public:  true,
		    flagged: false,
          },
        },
        actions: actions,
      },
    ],
  };

  const decision = await cerbos.checkResources(cerbosPayload);
  console.log(decision.results)
})();
