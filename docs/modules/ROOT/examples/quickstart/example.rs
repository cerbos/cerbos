use cerbos::sdk::attr::attr;
use cerbos::sdk::model::{Principal, Resource, ResourceAction, ResourceList};
use cerbos::sdk::{CerbosAsyncClient, CerbosClientOptions, CerbosEndpoint, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let opt =
        CerbosClientOptions::new(CerbosEndpoint::HostPort("localhost", 3593)).with_plaintext();
    let mut client = CerbosAsyncClient::new(opt).await?;

    let principal =
        Principal::new("bugs_bunny", ["user"]).with_attributes([attr("beta_tester", true)]);

    let actions: [&str; 2] = ["view:public", "comment"];

    let resp = client
        .check_resources(
            principal,
            ResourceList::new_from([
                ResourceAction(
                    Resource::new("BUGS001", "album:object").with_attributes([
                        attr("owner", "bugs_bunny"),
                        attr("public", false),
                        attr("flagged", false),
                    ]),
                    actions,
                ),
                ResourceAction(
                    Resource::new("DAFFY002", "album:object").with_attributes([
                        attr("owner", "daffy_duck"),
                        attr("public", true),
                        attr("flagged", false),
                    ]),
                    actions,
                ),
            ]),
            None,
        )
        .await?;

    println!("{:?}", resp.response);

    Ok(())
}
