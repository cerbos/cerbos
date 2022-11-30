use cerbos::sdk::attr::{attr, StructVal};
use cerbos::sdk::model::{Principal, Resource, ResourceAction, ResourceList};
use cerbos::sdk::{CerbosAsyncClient, CerbosClientOptions, CerbosEndpoint, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let opt =
        CerbosClientOptions::new(CerbosEndpoint::HostPort("localhost", 3593)).with_plaintext();
    let mut client = CerbosAsyncClient::new(opt).await?;

    let principal = Principal::new("123", ["USER"]).with_attributes([attr(
        "workspaces",
        StructVal([
            ("workspaceA", StructVal([("role", "OWNER")])),
            ("workspaceB", StructVal([("role", "MEMBER")])),
        ]),
    )]);

    let actions: [&str; 2] = ["workspace:view", "pii:view"];

    let kind = "workspace";
    let resp = client
        .check_resources(
            principal,
            ResourceList::new_from([
                ResourceAction(Resource::new("workspaceA", kind), actions),
                ResourceAction(Resource::new("workspaceB", kind), actions),
            ]),
            None,
        )
        .await?;

    println!("{:?}", resp.response);

    Ok(())
}
