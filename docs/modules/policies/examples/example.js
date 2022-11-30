const { GRPC: Cerbos } = require("@cerbos/grpc");

const cerbos = new Cerbos("localhost:3593", { tls: false });

(async() => {
  const kind = "workspace";
  const actions = ["workspace:view", "pii:view"];

  const cerbosPayload = {
    principal: {
      id: "123",
      roles: ["USER"],
      attributes: {
        workspaces: {
          workspaceA: {
            role: "OWNER",
          },
          workspaceB: {
            role: "MEMBER",
          }
        },
      },
    },
    resources: [
      {
        resource: {
          kind: kind,
          id: "workspaceA",
        },
        actions: actions,
      },
      {
        resource: {
          kind: kind,
          id: "workspaceB",
        },
        actions: actions,
      },
    ],
  };

  const decision = await cerbos.checkResources(cerbosPayload);
  console.log(decision.results)
})();
