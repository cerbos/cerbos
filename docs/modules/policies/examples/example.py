import json

from cerbos.sdk.client import CerbosClient
from cerbos.sdk.model import Principal, Resource, ResourceAction, ResourceList
from fastapi import HTTPException, status

principal = Principal(
    "123",
    roles=["USER"],
    attr={
        "workspaces": {
            "workspaceA": {
                "role": "OWNER"
            },
            "workspaceB": {
                "role": "MEMBER",
                "pii": True,
                "functions": {
                    "view": {
                        "all": True
                    },
                    "manage": {
                        "all": False,
                        "functions": [
                            "function2"
                        ]
                    }
                },
                "sources": {
                    "tags": [
                        "env:stg"
                    ]
                }
            }
        }
    }
)

actions = ["workspace:view", "pii:view"]
resource_list = ResourceList(
    resources=[
        ResourceAction(
            Resource(
                "workspaceA",
                "workspace",
                attr={
                    "location": "EU",
                },
            ),
            actions=actions,
        ),
        ResourceAction(
            Resource(
                "workspaceB",
                "workspace",
                attr={
                    "location": "US",
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
