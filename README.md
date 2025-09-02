![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cerbos/cerbos?color=green&logo=github&sort=semver)  [![Snapshots](https://github.com/cerbos/cerbos/actions/workflows/snapshot.yaml/badge.svg)](https://github.com/cerbos/cerbos/actions/workflows/snapshot.yaml)  [![Go Report Card](https://goreportcard.com/badge/github.com/cerbos/cerbos)](https://goreportcard.com/report/github.com/cerbos/cerbos)  [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md)

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/supplemental-ui/logo.png?raw=true" alt="Cerbos"/>
</p>

## What is Cerbos?

Cerbos is an authorization layer that evolves with your product. It enables you to define powerful, context-aware access control rules for your application resources in simple, intuitive YAML policies; managed and deployed via your Git-ops infrastructure. It provides highly available APIs to make simple requests to evaluate policies and make dynamic access decisions for your application.

This repo has everything you need to set up a self-hosted Cerbos Policy Decision Point (PDP). [Sign up for a free Cerbos Hub account](https://cerbos.dev/product-cerbos-hub?utm_campaign=brand_cerbos&utm_source=github) to streamline your policy authoring and distribution workflow to self-hosted PDPs.

With Cerbos Hub you can:

- Collaborate with colleagues to author and share policies in fully-interactive private playgrounds
- Quickly and efficiently distribute policy updates to your whole PDP fleet
- Build special policy bundles for client-side or in-browser authorization
- Easily integrate with Cerbos in serverless and edge deployments

## Key concepts, at a glance 👀

**_PRINCIPAL:_** oftentimes just the "user", but can also represent: other applications, services, bots or anything you can think of. The "thing" that's trying to carry out an... ↙️

**_ACTION:_** a specific task. Whether to create, view, update, delete, acknowledge, approve... anything. The principal might have permission to do all actions or maybe just one or two. The actions are carried out on a... ↙️

**_RESOURCE:_** the thing you're controlling access to. It could be anything, e.g., in an expense management system; reports, receipts, card details, payment records, etc. You define resources in Cerbos by writing... ↙️

**_POLICIES:_** YAML files where you define the access rules for each resource, following a [simple, structured format](#resource-policy). Stored either: [on disk](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#disk-driver), in [cloud object stores](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#blob-driver), [git repos](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#git-driver), or dynamically in [supported databases](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#sqlite3). These are continually monitored by the... ↙️

**_CERBOS PDP:_** the Policy Decision Point: the stateless service where policies are executed and decisions are made. This runs as a separate process in kube (as a [service](https://docs.cerbos.dev/cerbos/latest/deployment/k8s-service.html) or a [sidecar](https://docs.cerbos.dev/cerbos/latest/deployment/k8s-sidecar.html)), directly as a [systemd service](https://docs.cerbos.dev/cerbos/latest/deployment/systemd.html) or as an [AWS Lambda function](https://docs.cerbos.dev/cerbos/latest/deployment/serverless-faas.html). Once deployed, the PDP provides two primary APIs...

* **_CheckResources:_** "Can this principal access this resource?"
* **_PlanResources:_** "Which of resource kind=X can this principal access?"

These APIs can be called via [cURL](#api-request), or in production via one of our many... ↙️

**_SDKs:_** you can see the list [here](#client-sdks). There are also a growing number of [query plan adapters](#query-plan-adapters) to convert the SDK `PlanResources` responses to a convenient query instance.

**_RBAC -> ABAC:_** If simple RBAC doesn't cut it, you can extend the decision-making by implementing attribute based rules. Implement `conditions` in your resource policies which are evaluated dynamically at runtime using contextual data, for much more granular control. Add conditions in [derived roles](https://docs.cerbos.dev/cerbos/latest/policies/derived_roles.html) to extend the RBAC roles dynamically. Or use [principal policies](https://docs.cerbos.dev/cerbos/latest/policies/principal_policies.html) for more particular overrides for a specific user.

**_CERBOS HUB:_** A cloud-hosted control plane to streamline your Cerbos PDP deployment. Includes a comprehensive CI/CD solution for testing and distributing policy updates securely and efficiently, collaborative private playgrounds for quick prototyping and experimentation, and an exclusive Embedded PDP solution for deploying your policies to browsers and serverless/edge applications.

## How Cerbos PDP works with your application:

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/modules/ROOT/assets/images/how_cerbos_works.png?raw=true" alt="Cerbos"/>
</p>

Learn more about how Cerbos PDP and Cerobs Hub work together to solve your authorization headaches [here](https://cerbos.dev/how-it-works?utm_campaign=brand_cerbos&utm_source=github).

## Learn more

* Get up and running quickly with our [quickstart](https://docs.cerbos.dev/cerbos/latest/quickstart.html), or build an example implementation in our [tutorial](https://docs.cerbos.dev/cerbos/latest/tutorial/00_intro.html)
* See [example policies and requests](#examples)
* Read the [full documentation](https://docs.cerbos.dev)
* Explore some of our [demo repositories](https://github.com/cerbos)
* Try online with the [Cerbos playground](https://play.cerbos.dev)
* Learn more about [Cerbos Hub](https://cerbos.dev/product-cerbos-hub?utm_campaign=brand_cerbos&utm_source=github) and make an account

## Used by

Cerbos is popular among large and small organizations:

<p align="center">
  <img src="https://cerbos.dev/assets/logos/readme_logos.png" alt="Cerbos"/>
</p>


_Using Cerbos? Let us know by emailing devrel@cerbos.dev._


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

* [Go](https://github.com/cerbos/cerbos-sdk-go)
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

We collect anonymous usage data to help us improve the product. You can opt out by setting the `CERBOS_NO_TELEMETRY=1` environment variable. For more information about what data we collect and other ways to opt out, see the [telemetry documentation](https://docs.cerbos.dev/cerbos/latest/configuration/telemetry.html).

## Join the community on Slack 💬

<a href="http://go.cerbos.io/slack"><img src="https://i.ibb.co/GxJfc1Q/cerbos-slack-btn.png" width="200"></a>

## 🔗 Links
- [Newsletter](https://cerbos.dev/subscribe)
- [Home page](https://cerbos.dev)
- [Contribution Guidelines](CONTRIBUTING.md)
- [Run cerbos Locally](https://docs.cerbos.dev/cerbos/latest/tutorial/01_running-locally)

## Stargazers ⭐

[![Stargazers repo roster for cerbos/cerbos](https://bytecrank.com/nastyox/reporoster/php/stargazersSVG.php?user=cerbos&repo=cerbos)](https://github.com/cerbos/cerbos)

## 🛡️ License

Cerbos is licensed under the Apache License 2.0 - see the [LICENSE](https://github.com/cerbos/cerbos/blob/main/LICENSE) file for details.

## 💪 Thanks To All Contributors

Thanks a lot for spending your time helping Cerbos grow. Keep rocking 🥂

<a>
  <img src="https://contributors-img.web.app/image?repo=cerbos/cerbos" alt="Contributors"/>
</a>


## AuthZEN Translation Layer

Cerbos can expose a minimal OpenID AuthZEN-compatible HTTP API as a translation layer to the existing CheckResources API.

Configuration (YAML):

```yaml
server:
  # Enable the AuthZEN translation layer
  authzen:
    enabled: true
    # Listen address for the AuthZEN HTTP server (TCP or unix: socket)
    # Defaults to ":3595" if not set
    listenAddr: ":3595"
```

Endpoints (served by the AuthZEN server):
- `/.well-known/authzen-configuration` (metadata)
- `POST /access/v1/evaluation`
- `POST /access/v1/evaluations`

Notes:
- Only evaluation endpoints are implemented. Subject/Resource/Action search endpoints are not implemented and are intentionally omitted from metadata.
- Requests are translated to Cerbos CheckResources calls. The `subject.properties.roles` field is required.
- AuthZEN `context`, if present, is embedded under `$context` inside the principal attributes for policy evaluation.
- TLS is supported via the standard `server.tls` configuration. When TLS is enabled, the metadata `policy_decision_point` will use the `https` scheme, and all AuthZEN endpoints are served over TLS (access them via `https://`).
