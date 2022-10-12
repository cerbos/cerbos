![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cerbos/cerbos?color=green&logo=github&sort=semver)  [![Snapshots](https://github.com/cerbos/cerbos/actions/workflows/snaphot.yaml/badge.svg)](https://github.com/cerbos/cerbos/actions/workflows/snaphot.yaml)  [![Go Reference](https://pkg.go.dev/badge/github.com/cerbos/cerbos/client.svg)](https://pkg.go.dev/github.com/cerbos/cerbos/client)   [![Go Report Card](https://goreportcard.com/badge/github.com/cerbos/cerbos)](https://goreportcard.com/report/github.com/cerbos/cerbos)  [![codecov](https://codecov.io/gh/cerbos/cerbos/branch/main/graph/badge.svg?token=tGaxiUZUzL)](https://codecov.io/gh/cerbos/cerbos)  [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md)

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/supplemental-ui/logo.png?raw=true" alt="Cerbos"/>
</p>

## What is Cerbos?

Cerbos is an authorization layer that evolves with your product. It enables you to define powerful, context-aware access control rules for your application resources in simple, intuitive YAML policies; managed and deployed via your Git-ops infrastructure. It provides highly available APIs to make simple requests to evaluate policies and make dynamic access decisions for your application.

## Key concepts, at a glance 👀

**_PRINCIPAL:_** oftentimes just the "user", but can also represent: other applications, services, bots or anything you can think of. The "thing" that's trying to carry out an... ↙️

**_ACTION:_** a specific task. Whether it be to create, view, update, delete, acknowledge, approve... anything at all. The principal might have permission to do all actions, or maybe just one or two. The actions are carried out on a... ↙️

**_RESOURCE:_** the thing you're controlling access to. Could be anything, e.g. in an expense management system; reports, receipts, card details, payment records, etc. You define resources in Cerbos by writing... ↙️

**_POLICIES:_** YAML files where you define the access rules for each resource, following a [simple, structured format](#resource-policy). Stored either: [on disk](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#disk-driver), in [cloud object stores](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#blob-driver), [git repos](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#git-driver), or dynamically in [supported databases](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#sqlite3). These are continually monitored by the... ↙️

**_CERBOS PDP:_** the Policy Decision Point: the stateless service where policies are executed and decisions are made. This runs as a separate process, in kube (as a [service](https://docs.cerbos.dev/cerbos/latest/deployment/k8s-service.html) or a [sidecar](https://docs.cerbos.dev/cerbos/latest/deployment/k8s-sidecar.html)), directly as a [systemd service](https://docs.cerbos.dev/cerbos/latest/deployment/systemd.html) or as an [AWS Lambda function](https://docs.cerbos.dev/cerbos/latest/deployment/serverless-faas.html). Once deployed, the PDP provides two primary APIs...

* **_CheckResources:_** "Can this principal access this resource?"
* **_PlanResources:_** "Which of resource kind=X can this principal access?"

These APIs can be called via [cURL](#api-request), or in production via one of our many... ↙️

**_SDKs:_** you can see the list [here](#client-sdks). There are also a growing number of [query plan adapters](#query-plan-adapters), to convert the SDK `PlanResources` responses to a convenient query instance.

**_RBAC -> ABAC:_** If simple RBAC doesn't cut it, you can extend the decision-making by implementing attribute based rules. Implement `conditions` in your resource policies which are evaluated dynamically at runtime using contextual data, for much more granular control. Add conditions in [derived roles](https://docs.cerbos.dev/cerbos/latest/policies/derived_roles.html) to dynamically extend the RBAC roles. Or use [principal policies](https://docs.cerbos.dev/cerbos/latest/policies/principal_policies.html) for more particular overrides for a specific user.

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/modules/ROOT/assets/images/how_cerbos_works.png?raw=true" alt="Cerbos"/>
</p>

## Learn more

* Get up and running quickly with our [quickstart](https://docs.cerbos.dev/cerbos/latest/quickstart.html), or build an example implemention in our [tutorial](https://docs.cerbos.dev/cerbos/latest/tutorial/00_intro.html)
* See [example policies and requests](#examples)
* Read the [full documentation](https://docs.cerbos.dev)
* Explore some of our [demo repositories](https://github.com/cerbos)
* Try online with the [Cerbos playground](https://play.cerbos.dev)

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

Join Slack 👇

<a href="http://go.cerbos.io/slack"><img src="https://i.ibb.co/GxJfc1Q/cerbos-slack-btn.png" width="200"></a>

Subscribe to our [Newsletter](https://cerbos.dev/subscribe)

## Contributing ⌨️

Check out [how to contribute](CONTRIBUTING.md).

## Stargazers ⭐

[![Stargazers repo roster for cerbos/cerbos](https://reporoster.com/stars/cerbos/cerbos)](https://github.com/cerbos/cerbos)
