[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cerbos/cerbos?color=green&logo=github&sort=semver)](https://github.com/cerbos/cerbos/releases/latest)  [![Snapshots](https://github.com/cerbos/cerbos/actions/workflows/snapshot.yaml/badge.svg)](https://github.com/cerbos/cerbos/actions/workflows/snapshot.yaml)  [![Go Report Card](https://goreportcard.com/badge/github.com/cerbos/cerbos)](https://goreportcard.com/report/github.com/cerbos/cerbos)  [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md)  [![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)  [![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/cerbosdev?style=social)](https://x.com/cerbosdev)  [![LinkedIn](https://img.shields.io/badge/LinkedIn-cerbos--dev-0A66C2?logo=linkedin)](https://www.linkedin.com/company/cerbos-dev/)

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/supplemental-ui/logo.png?raw=true" alt="Cerbos"/>
</p>
<p align="center">
<b>Cerbos authorization management platform</b>
<br/>
Authorize every identity. Govern every action.
</p>

[Docs](https://docs.cerbos.dev/cerbos/latest/index.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) · [Quickstart](https://docs.cerbos.dev/cerbos/latest/quickstart.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) · [Playground](https://play.cerbos.dev/?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) · [Slack community](https://community.cerbos.dev/?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) · [Cerbos platform](https://www.cerbos.dev/how-it-works?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) · [Blog](https://www.cerbos.dev/blog?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro)

## What is Cerbos?

Cerbos is an authorization management platform. It authorizes every identity and governs every action across applications, gateways, workloads, and AI agents.

The platform has four components:

* [Cerbos PDP](https://docs.cerbos.dev/cerbos/latest/?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) is the open source engine that makes authorization decisions.
* [Client SDKs and integrations](https://www.cerbos.dev/ecosystem?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) enforce those decisions in your applications.
* [Cerbos Hub](https://docs.cerbos.dev/cerbos-hub/?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) handles policy authoring, testing, distribution, and audit.
* [Cerbos Synapse](https://docs.cerbos.dev/synapse/latest/?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) fetches the data each decision needs from the systems you already run.

<p align="center">
  <a href="https://www.youtube.com/watch?v=0DDin9I0abc"><img src="https://img.youtube.com/vi/0DDin9I0abc/maxresdefault.jpg" alt="How Cerbos works (video)" width="640"/></a>
</p>

**This repository contains Cerbos PDP, the open source policy decision point at the core of the platform.** Cerbos PDP is stateless, AuthZEN compliant, and scales horizontally. It runs in containers, on Kubernetes, in serverless functions, and at the edge. Policies are YAML files that you version in Git alongside your code.

Cerbos PDP is licensed under [Apache 2.0](LICENSE) and is production ready. It has no feature flags, no license keys, and no limits on authorization checks, services, or environments.

Cerbos PDP evaluates policies. Policy testing, distribution to every instance, decision log collection, and data fetching are separate concerns. You can build them yourself or use the rest of the platform. [Running Cerbos PDP in production](#running-cerbos-pdp-in-production) summarizes the difference, and [Open source core vs the complete Cerbos solution](https://www.cerbos.dev/blog/open-source-vs-paid-cerbos?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) has the full comparison.

## Key concepts, at a glance

Four terms describe every authorization request that Cerbos evaluates.

**PRINCIPAL** is the user or process that makes the request, such as a person, a service account, a bot, or an AI agent. A principal has an ID, the roles it holds in your identity provider, and any attributes that your policies use.

**ACTION** is the operation that the principal wants to perform. Actions can be coarse-grained, such as `create` or `view`, or fine-grained, such as `view:public` or `update:invoice_amt`. Your application defines the set of actions.

**RESOURCE** is the kind of object that the principal wants to access, such as an invoice or a leave request. Each request identifies a specific resource instance by ID.

**POLICY** is a YAML file that contains the access rules for a resource. See the [resource policy example](#resource-policy). Cerbos PDP loads policies from [disk](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro#disk-driver), [cloud object stores](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro#blob-driver), [Git repositories](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro#git-driver), or [databases](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro#sqlite3), and detects changes to them.

[Resource policies](https://docs.cerbos.dev/cerbos/latest/policies/resource_policies.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) are the primary policy type. Cerbos also supports [principal policies](https://docs.cerbos.dev/cerbos/latest/policies/principal_policies.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) for overrides that apply to a specific principal, [derived roles](https://docs.cerbos.dev/cerbos/latest/policies/derived_roles.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) for roles assigned at request time such as `owner`, [role policies](https://docs.cerbos.dev/cerbos/latest/policies/role_policies.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) for rules defined per role, and [exported variables and constants](https://docs.cerbos.dev/cerbos/latest/policies/variables.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) for expressions shared across policies.

Rules start with roles. [Conditions](https://docs.cerbos.dev/cerbos/latest/policies/conditions.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro) are CEL expressions evaluated against request attributes. Add them when roles alone are not sufficient, which extends a policy from RBAC to ABAC without a new policy structure.

## How Cerbos PDP works with your application

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/modules/ROOT/assets/images/how_cerbos_works.png?raw=true" alt="How Cerbos PDP works with your application"/>
</p>

Your application sends Cerbos PDP the principal, the resource, and the actions. Cerbos PDP evaluates the request against your policies and returns a decision. It serves HTTP on port 3592 and gRPC on port 3593.

Cerbos PDP has two primary APIs:

* [CheckResources](https://docs.cerbos.dev/cerbos/latest/api/index.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro#check-resources) returns whether a principal can perform each action on specific resource instances.
* [PlanResources](https://docs.cerbos.dev/cerbos/latest/api/index.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro#resources-query-plan) returns a filter that you apply to your data store, so that a query returns only the records the principal can access.

Call the APIs over HTTP, as in the [API request example](#api-request), or with a [client SDK](#sdks-and-adapters).

## Used by

<p align="center">
  <img src="https://cerbos.dev/assets/logos/readme_logos.png" alt="Logos of organizations that use Cerbos"/>
</p>

Organizations of all sizes run Cerbos in production. See the [customer stories](https://www.cerbos.dev/customers?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_intro).

## Installation

* [Container](https://docs.cerbos.dev/cerbos/latest/installation/container.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production)
* [Binary/OS packages](https://docs.cerbos.dev/cerbos/latest/installation/binary.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production)
* [Helm Chart](https://docs.cerbos.dev/cerbos/latest/installation/helm.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production)

## Running Cerbos PDP in production

Cerbos PDP is stateless. Instances do not coordinate with each other or share a database, so you can run as many as you need. On Kubernetes, run it as a [sidecar](https://docs.cerbos.dev/cerbos/latest/deployment/k8s-sidecar.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production), a [DaemonSet](https://docs.cerbos.dev/cerbos/latest/deployment/k8s-daemonset.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production), or a [service](https://docs.cerbos.dev/cerbos/latest/deployment/k8s-service.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production). Outside Kubernetes, run it as a [systemd service](https://docs.cerbos.dev/cerbos/latest/deployment/systemd.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production), an [AWS Lambda function](https://docs.cerbos.dev/cerbos/latest/deployment/serverless-faas.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production), or a standalone service behind a load balancer. See [deployment models](https://docs.cerbos.dev/cerbos/latest/deployment/index.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production).

Git is the preferred policy store. Each instance checks the store independently, so during a rollout different instances can briefly serve different policy versions. See [storage drivers](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production).

Audit logging is disabled by default. Enable it before you need the records. The local backend stores decisions on disk for queries with `cerbosctl`. The file backend writes newline-delimited JSON for an existing log pipeline. The Kafka backend publishes to a Kafka topic. See [audit configuration](https://docs.cerbos.dev/cerbos/latest/configuration/audit.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production).

The rest of the [Cerbos platform](https://www.cerbos.dev/how-it-works?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production) changes these operations as follows:

|  | Cerbos PDP only | Cerbos platform |
| :--- | :--- | :--- |
| **Policy changes** | You add policy tests to your CI and roll out changes yourself. | Tests run on every commit. A failing test blocks the rollout. |
| **Instance consistency** | Each instance pulls policies from your Git repository or bucket on the interval you configure. | Every instance receives the same policies within seconds, without a redeploy. |
| **Decision logs** | Each instance writes its own logs until you build collection. | Logs from every instance are searchable in one place and linked to the policy version. |
| **Decision data** | Each service fetches user and resource attributes before it calls Cerbos PDP. | Your application sends a user ID. Cerbos Synapse fetches the rest from your identity provider or database. |

Policies and integrations that you build on Cerbos PDP continue to work on the platform. Moving to it is a configuration change. Community support for Cerbos PDP is available on Slack, and commercial support is included with the platform. [Start with Cerbos Hub for free](https://hub.cerbos.cloud/?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production) or [see pricing](https://www.cerbos.dev/pricing?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_production).

## Examples

#### Resource policy

A resource policy defines the access rules for one resource kind.

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

Derived roles assign additional roles to a principal based on request attributes.

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

## SDKs and adapters

We maintain all of these, and they all talk to the same [Cerbos API](https://docs.cerbos.dev/cerbos/latest/api/index.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_learnmore).

**Client SDKs** call Cerbos PDP from your application and handle the connection and serialization: [Go](https://github.com/cerbos/cerbos-sdk-go), [Java](https://github.com/cerbos/cerbos-sdk-java), [JavaScript](https://github.com/cerbos/cerbos-sdk-javascript), [.NET](https://github.com/cerbos/cerbos-sdk-net), [PHP](https://github.com/cerbos/cerbos-sdk-php), [Python](https://github.com/cerbos/cerbos-sdk-python), [Ruby](https://github.com/cerbos/cerbos-sdk-ruby), [Rust](https://github.com/cerbos/cerbos-sdk-rust), and [Laravel](https://github.com/cerbos/cerbos-sdk-laravel).

**Query plan adapters** convert a `PlanResources` filter into a query for your ORM or database:

* JavaScript: [Prisma](https://github.com/cerbos/query-plan-adapters/tree/main/prisma), [Drizzle](https://github.com/cerbos/query-plan-adapters/tree/main/drizzle), [Mongoose](https://github.com/cerbos/query-plan-adapters/tree/main/mongoose), [Convex](https://github.com/cerbos/query-plan-adapters/tree/main/convex)
* Python: [SQLAlchemy](https://github.com/cerbos/query-plan-adapters/tree/main/sqlalchemy), [LangChain with ChromaDB](https://github.com/cerbos/query-plan-adapters/tree/main/langchain-chromadb)
* Go: [ent](https://github.com/cerbos/query-plan-adapters/tree/main/ent), [pgx](https://github.com/cerbos/query-plan-adapters/tree/main/pgx)
* Java: [Spring Data](https://github.com/cerbos/query-plan-adapters/tree/main/spring-data), [Elasticsearch](https://github.com/cerbos/query-plan-adapters/tree/main/elasticsearch-java)
* Ruby: [ActiveRecord](https://github.com/cerbos/query-plan-adapters/tree/main/activerecord)

## Telemetry

We collect anonymous usage data to help us improve the product. You can opt out by setting the `CERBOS_NO_TELEMETRY=1` environment variable. For more information about what data we collect and other ways to opt out, see the [telemetry documentation](https://docs.cerbos.dev/cerbos/latest/configuration/telemetry.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_learnmore).

## Join the community on Slack

<a href="https://community.cerbos.dev/?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_learnmore"><img src="https://i.ibb.co/GxJfc1Q/cerbos-slack-btn.png" alt="Join the Cerbos community on Slack" width="200"></a>

## Community and links

* [Slack community](https://community.cerbos.dev/?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_learnmore) for questions and help from the Cerbos team and other users
* [Newsletter](https://cerbos.dev/subscribe?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_learnmore) for product updates
* [Tutorial](https://docs.cerbos.dev/cerbos/latest/tutorial/00_intro.html?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_learnmore) for building a complete example
* [Cerbos playground](https://play.cerbos.dev/?utm_campaign=brand_cerbos&utm_source=github&utm_content=readme_learnmore) for writing and testing policies in the browser
* [Examples](#examples) of policies and requests on this page
* [Demo repositories](https://github.com/cerbos) with example applications
* [Contribution guidelines](CONTRIBUTING.md) for sending a pull request

## 🛡️ License

Cerbos is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Big thank you to all contributors!

<a href="https://github.com/cerbos/cerbos/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=cerbos/cerbos" alt="Contributors"/>
</a>
