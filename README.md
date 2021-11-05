![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cerbos/cerbos?color=green&logo=github&sort=semver) [![Go Reference](https://pkg.go.dev/badge/github.com/cerbos/cerbos/client.svg)](https://pkg.go.dev/github.com/cerbos/cerbos/client)  [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md)  [![Snapshots](https://github.com/cerbos/cerbos/actions/workflows/snaphot.yaml/badge.svg)](https://github.com/cerbos/cerbos/actions/workflows/snaphot.yaml)
 
<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/supplemental-ui/logo.png?raw=true" alt="Cerbos"/>
</p>

Painless access control for cloud-native applications
========================================================

Cerbos helps you super-charge your authorization implementation by writing context-aware access control policies for your application resources. Author access rules using an intuitive YAML configuration language, use your Git-ops infrastructure to test and deploy them and, make simple API requests to the Cerbos PDP to evaluate the policies and make dynamic access decisions.


* [Try online with the Cerbos playground](https://play.cerbos.dev)
* [Explore demo repositories](https://github.com/cerbos)
* [Read the documentation](https://docs.cerbos.dev)
* [Subscribe to our newsletter](https://cerbos.dev/subscribe)
* [Join the community on Slack](http://go.cerbos.io/slack)
* Install Cerbos
    * [Container](https://docs.cerbos.dev/cerbos/latest/installation/container.html)
    * [Binary](https://docs.cerbos.dev/cerbos/latest/installation/binary.html)
    * [Helm Chart](https://docs.cerbos.dev/cerbos/latest/installation/helm.html)
* Get the client SDKs
    * [Go](client/README.md)
    * [Java](https://github.com/cerbos/cerbos-sdk-java)
    * [NodeJS](https://github.com/cerbos/cerbos-sdk-node)
* [Contribute](CONTRIBUTING.md)


How it works
------------

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/modules/ROOT/assets/images/how_cerbos_works.png?raw=true" alt="Cerbos"/>
</p>


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

**API response**

```json
{
  "requestId": "test01",
  "resourceInstances": {
    "XX125": {
      "actions": {
        "view": "EFFECT_ALLOW"
      }
    }
  }
}
```


Stargazers
-----------
[![Stargazers repo roster for cerbos/cerbos](https://reporoster.com/stars/cerbos/cerbos)](https://github.com/cerbos/cerbos)

