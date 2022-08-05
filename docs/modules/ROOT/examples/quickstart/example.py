import json

from cerbos.sdk.client import CerbosClient
from cerbos.sdk.model import Principal, Resource, ResourceAction, ResourceList
from fastapi import HTTPException, status

principal = Principal(
    "bugs_bunny",
    roles=["user"],
    attr={
        "beta_tester": True,
    },
)

actions = ["view:public", "comment"]
resource_list = ResourceList(
    resources=[
        ResourceAction(
            Resource(
                "BUGS001",
                "album:object",
                attr={
                    "owner": "bugs_bunny",
                    "public": False,
                    "flagged": False,
                },
            ),
            actions=actions,
        ),
        ResourceAction(
            Resource(
                "DAFFY002",
                "album:object",
                attr={
                    "owner": "daffy_duck",
                    "public": True,
                    "flagged": False,
                },
            ),
            actions=actions,
        ),
    ],
)

with CerbosClient(host="http://localhost:3592") as c:
    try:
        resp = c.check_resources(principal=principal, resources=resource_list)
        resp.raise_if_failed()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized"
        )

print(json.dumps(resp.to_dict(), sort_keys=False, indent=4))
