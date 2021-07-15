Cerbos: Painless access management for cloud-native applications
================================================================

Cerbos helps you super-charge your authorization implementation by writing context-aware access control policies for your application resources. Author access rules using an intuitive YAML configuration language, use your Git-ops infrastructure to test and deploy them and, make simple API requests to the Cerbos PDP to evaluate the policies and make dynamic access decisions.

See https://docs.cerbos.dev for full Cerbos documentation.

Example
------

**Derived roles**: Dynamically assign new roles to users based on contextual data.

```yaml
---
apiVersion: "api.cerbos.dev/v1"
derivedRoles:
  name: common_roles
  definitions:
    - name: owner
      parentRoles: ["user"]
      condition:
        match:
          expr: request.resource.attr.owner == request.principal.id

    - name: abuse_moderator
      parentRoles: ["moderator"]
      condition:
        match:
          expr: request.resource.attr.flagged == true
```

**Resource policy**: Write access rules for a resource.

```yaml
---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  importDerivedRoles:
    - common_roles
  resource: "album:object"
  version: "default"
  rules:
    - actions: ['*']
      effect: EFFECT_ALLOW
      derivedRoles:
        - owner

    - actions: ['view', 'flag']
      effect: EFFECT_ALLOW
      roles:
        - user
      condition:
        match:
          expr: request.resource.attr.public == true

    - actions: ['view', 'delete']
      effect: EFFECT_ALLOW
      derivedRoles:
        - abuse_moderator
```

**API request**

```sh
cat <<EOF | curl --silent "http://localhost:3592/api/check?pretty" -d @-
{
  "requestId":  "test01",
  "actions":  ["view"],
  "resource":  {
    "kind":  "album:object",
    "instances": {
      "XX125": {
        "attr":  {
          "owner":  "alicia",
          "id":  "XX125",
          "public": false,
          "flagged": false
        }
      }
    }
  },
  "principal":  {
    "id":  "alicia",
    "roles":  ["user"]
  }
}
EOF
```




