![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cerbos/cerbos?color=green&logo=github&sort=semver)  [![Snapshots](https://github.com/cerbos/cerbos/actions/workflows/snaphot.yaml/badge.svg)](https://github.com/cerbos/cerbos/actions/workflows/snaphot.yaml)  [![Go Reference](https://pkg.go.dev/badge/github.com/cerbos/cerbos/client.svg)](https://pkg.go.dev/github.com/cerbos/cerbos/client)   [![Go Report Card](https://goreportcard.com/badge/github.com/cerbos/cerbos)](https://goreportcard.com/report/github.com/cerbos/cerbos)  [![codecov](https://codecov.io/gh/cerbos/cerbos/branch/main/graph/badge.svg?token=tGaxiUZUzL)](https://codecov.io/gh/cerbos/cerbos)  [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md)

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/supplemental-ui/logo.png?raw=true" alt="Cerbos"/>
</p>

Painless access control for your software
========================================================

Cerbos helps you super-charge your authorization implementation by writing context-aware access control policies for your application resources. Author access rules using an intuitive YAML configuration language, use your Git-ops infrastructure to test and deploy them and, make simple API requests to the Cerbos PDP to evaluate the policies and make dynamic access decisions.


## Key concepts, at a glance ⌛

**_PRINCIPAL:_** oftentimes just the "user", but can also represent: other applications, services, bots or anything you can think of. The "thing" that's trying to access the... ↙️

**_RESOURCE:_** the thing you're controlling access to. Could be anything, e.g. in an expense management system; reports, receipts, card details, payment records, etc. You define resources in Cerbos by writing... ↙️

**_POLICIES:_** YAML files where you define the access rules for each resource, following a [simple, structured format](#resource-policy). Stored either: [on disk](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#disk-driver), in [cloud object stores](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#blob-driver), [git repos](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#git-driver), or dynamically in [supported databases](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#sqlite3). These are continually monitored by the... ↙️

**_CERBOS PDP:_** the Policy Decision Point: the stateless service where policies are executed and decisions are made. This runs as a separate process, in kube (as a [service](https://docs.cerbos.dev/cerbos/latest/deployment/k8s-service.html) or a [sidecar](https://docs.cerbos.dev/cerbos/latest/deployment/k8s-sidecar.html)), directly as a [systemd service](https://docs.cerbos.dev/cerbos/latest/deployment/systemd.html) or as an [AWS Lambda function](https://docs.cerbos.dev/cerbos/latest/deployment/serverless-faas.html). Once deployed, the PDP provides two primary APIs...

* **_CheckResources:_** "Can this principal access this resource?"
* **_PlanResources:_** "Which of resource kind=X can this principal access?"

These APIs can be called via [cURL](#api-request), or in production via one of our many... ↙️

**_SDKs:_** you can see the list [here](#client-sdks). There are also a growing number of [query plan adapters](#query-plan-adapters), to convert the SDK `PlanResources` responses to a convenient query instance.

**_RBAC -> ABAC:_** If simple RBAC doesn't cut it, you can extend the decision-making by implementing attribute based rules. Implement attribute based `conditions` in your resource policies. Use [derived roles](https://docs.cerbos.dev/cerbos/latest/policies/derived_roles.html) to augment the RBAC roles with contextual data, dynamically at run-time, for much more granular control. Or use [principal policies](https://docs.cerbos.dev/cerbos/latest/policies/principal_policies.html) for more particular overrides for a specific user.

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/modules/ROOT/assets/images/how_cerbos_works.png?raw=true" alt="Cerbos"/>
</p>

## Further reading 📚

Read the full documentation [here](https://docs.cerbos.dev), explore some of our [demo repositories](https://github.com/cerbos), or try online with the [Cerbos playground](https://play.cerbos.dev).

## Used by

Cerbos is popular among large and small organizations:

<table cellspacing="1" cellpadding="0">
  <tr>
    <td valign="center">
      <a href="https://uw.co.uk">
        <img src="https://cerbos.dev/assets/uw.svg" width="256" />
      </a>
    </td>
    <td valign="center">
      <a href="https://withloop.co/">
        <img src="https://cerbos.dev/assets/loop.png"  width="256" />
      </a>
    </td>
    <td valign="center">
      <a href="https://9fin.com">
        <img src="https://cerbos.dev/assets/9fin.svg" width="256" height="35" />
      </a>
    </td>
    <td valign="center">
      <a href="https://salesroom.com">
        <img src="https://cerbos.dev/assets/salesroom.svg" width="256" />
      </a>
    </td>
  </tr>
  <tr>
    <td valign="center">
      <a href="https://refine.dev">
        <img src="https://cerbos.dev/assets/refine.png" width="256" />
      </a>
    </td>
    <td valign="center">
      <a href="https://www.doorfeed.com/">
        <img src="https://cerbos.dev/assets/doorfeed.svg" width="256" />
      </a>
    </td>
   <td valign="center">
      <a href="https://www.debite.io/">
        <img src="https://cerbos.dev/assets/debite.svg" width="256" />
      </a>
   </td>
   <td valign="center">
      <a href="https://www.wizeline.com/">
        <img src="https://cerbos.dev/assets/wizeline.svg" width="256" height="35"/>
      </a>
   </td>
  </tr>
</table>

_Using Cerbos? Open a PR to add your company._


## Installation

* [Container](https://docs.cerbos.dev/cerbos/latest/installation/container.html)
* [Binary/OS packages](https://docs.cerbos.dev/cerbos/latest/installation/binary.html)
* [Helm Chart](https://docs.cerbos.dev/cerbos/latest/installation/helm.html)


## Examples

#### Resource policy

Write access rules for a resource.

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

#### Derived roles

Dynamically assign new roles to users based on contextual data.

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

#### API request

```sh
cat <<EOF | curl --silent "http://localhost:3592/api/check/resources?pretty" -d @-
{
  "requestId": "test01",
  "includeMeta": true,
  "principal": {
    "id": "alicia",
    "roles": [
      "user"
    ]
  },
  "resources": [
    {
      "actions": [
        "view"
      ],
      "resource": {
        "id": "XX125",
        "kind": "album:object",
        "attr": {
          "owner": "alicia",
          "public": false,
          "flagged": false
        }
      }
    }
  ]
}
EOF
```

#### API response

```json
{
  "requestId": "test01",
  "results": [
    {
      "resource": {
        "id": "XX125",
        "kind": "album:object",
        "policyVersion": "default"
      },
      "actions": {
        "view": "EFFECT_ALLOW"
      },
      "meta": {
        "actions": {
          "view": {
            "matchedPolicy": "resource.album_object.vdefault"
          }
        },
        "effectiveDerivedRoles": [
          "owner"
        ]
      }
    }
  ]
}
```

## Client SDKs

* [Go](client/README.md)
* [Java](https://github.com/cerbos/cerbos-sdk-java)
* [JavaScript](https://github.com/cerbos/cerbos-sdk-javascript)
* [.NET](https://github.com/cerbos/cerbos-sdk-net)
* [PHP](https://github.com/cerbos/cerbos-sdk-php)
* [Python](https://github.com/cerbos/cerbos-sdk-python)
* [Ruby](https://github.com/cerbos/cerbos-sdk-ruby)
* [Rust](https://github.com/cerbos/cerbos-sdk-rust)

## Query plan adapters

* [Prisma](https://github.com/cerbos/query-plan-adapters/tree/main/prisma)
* [SQLAlchemy](https://github.com/cerbos/query-plan-adapters/tree/main/sqlalchemy)

## Telemetry

We collect anonymous usage data to help us improve the product. You can opt out by setting the `CERBOS_NO_TELEMETRY=1` environment variable. For more information about what data we collect and other ways to opt out, see the [telemetry documentation](https://docs.cerbos.dev/cerbos/latest/telemetry.html).

## Join the community 💬

Subscribe to our [newsletter](https://cerbos.dev/subscribe), or join the community on [Slack](http://go.cerbos.io/slack).

## Contributing ⌨️

Check out [how to contribute](CONTRIBUTING.md).

## Stargazers

[![Stargazers repo roster for cerbos/cerbos](https://reporoster.com/stars/cerbos/cerbos)](https://github.com/cerbos/cerbos)
