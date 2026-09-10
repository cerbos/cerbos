![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/cerbos/cerbos?color=green&logo=github&sort=semver)  [![Snapshots](https://github.com/cerbos/cerbos/actions/workflows/snapshot.yaml/badge.svg)](https://github.com/cerbos/cerbos/actions/workflows/snapshot.yaml)  [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md)

<p align="center">
  <img src="https://github.com/cerbos/cerbos/blob/main/docs/supplemental-ui/logo.png?raw=true" alt="Cerbos"/>
</p>
<p align="center">
<b>Cerbos authorization management platform</b>
<br/>
Authorize every identity. Govern every action.
</p>


\[twitter @cerbosdev\]     \[linkedin @cerbos-dev\]


[Docs](https://docs.cerbos.dev/cerbos/latest/index.html?utm_campaign=brand_cerbos&utm_source=github) · [Quickstart](https://docs.cerbos.dev/cerbos/latest/quickstart.html?utm_campaign=brand_cerbos&utm_source=github) · [Slack community](https://community.cerbos.dev/?utm_campaign=brand_cerbos&utm_source=github) · [Full Cerbos platform](https://www.cerbos.dev/how-it-works?utm_campaign=brand_cerbos&utm_source=github) · [Blog](https://www.cerbos.dev/blog?utm_campaign=brand_cerbos&utm_source=github)

## What is Cerbos?

Cerbos is an end-to-end authorization management platform for authorizing every identity and governing every action across applications, gateways, workloads, and AI agents.

Four components work together to do that:

* The open source [Cerbos PDP](https://docs.cerbos.dev/cerbos/latest/?utm_campaign=brand_cerbos&utm_source=github) makes the decisions.  
* The [PEP SDKs](https://www.cerbos.dev/ecosystem?utm_campaign=brand_cerbos&utm_source=github) enforce them inside your applications.  
* [Cerbos Hub](https://docs.cerbos.dev/cerbos-hub/?utm_campaign=brand_cerbos&utm_source=github) handles policy authoring, testing, distribution and audit.  
* [Cerbos Synapse](https://docs.cerbos.dev/synapse/latest/?utm_campaign=brand_cerbos&utm_source=github) gathers the data each decision needs from the systems you already run.

.....

**This repo is the Cerbos Policy Decision Point (PDP), the open source engine at the core of the platform.** It is stateless, high performance, AuthZEN compliant, and built to scale horizontally, and it runs anywhere you run code, from containers and Kubernetes to serverless and the edge. Policies are YAML, versioned in Git alongside the rest of your code, and evaluated at runtime through a simple API.

The engine is [Apache 2.0](https://github.com/cerbos/cerbos?tab=Apache-2.0-1-ov-file), production ready, and free to run forever. No feature flags, no license keys, and no limit on authorization checks, services, or environments.

*Running the engine is one part of authorization. Testing every policy change, getting it out to every running instance, keeping a record of every decision, and pulling in the data each decision needs are the parts you build and maintain yourself. The rest of the Cerbos platform ([try it here](https://hub.cerbos.cloud/?utm_campaign=brand_cerbos&utm_source=github)) does those. Running the PDP in production below is the short version. [Open source core vs the complete Cerbos solution](https://www.cerbos.dev/blog/open-source-vs-paid-cerbos?utm_campaign=brand_cerbos&utm_source=github) has the full comparison.*

## Key concepts, at a glance

Four terms describe every authorization question Cerbos answers.

**PRINCIPAL** is the human user or automated process making the request. A user, a service account, a bot, or an AI agent. It carries an ID, the roles it holds in your identity provider, and any attributes your policies need.

**ACTION** is what the principal is trying to do. Coarse-grained like create, view, update or delete, or fine-grained like view:public and update:invoice\_amt. Your application decides what actions exist.

**RESOURCE** is the kind of thing being accessed, an invoice, a document, a leave request. You write one resource policy per kind. The specific invoice a request is about is a resource instance.

**POLICY** is a YAML file holding the access rules for a resource, following a simple, structured format. Policies are stored [on disk](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github#disk-driver), in [cloud object stores](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github#blob-driver), in [git repos](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github#git-driver), or dynamically in [supported databases](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github#sqlite3), and Cerbos PDP watches them for changes. [Resource policies](https://docs.cerbos.dev/cerbos/latest/policies/resource_policies.html?utm_campaign=brand_cerbos&utm_source=github) are the main kind. There are also [principal policies](https://docs.cerbos.dev/cerbos/latest/policies/principal_policies.html?utm_campaign=brand_cerbos&utm_source=github) for per-user exceptions, [derived roles](https://docs.cerbos.dev/cerbos/latest/policies/derived_roles.html?utm_campaign=brand_cerbos&utm_source=github) for roles worked out at request time such as owner or branch manager, [role policies](https://docs.cerbos.dev/cerbos/latest/policies/role_policies.html?utm_campaign=brand_cerbos&utm_source=github), and [exported variables and constants](https://docs.cerbos.dev/cerbos/latest/policies/variables.html?utm_campaign=brand_cerbos&utm_source=github) for expressions shared across policies.

Start with roles, then add [conditions](https://docs.cerbos.dev/cerbos/latest/policies/conditions.html?utm_campaign=brand_cerbos&utm_source=github) when roles alone stop being enough. Conditions are CEL expressions evaluated against the attributes in the request, which is how the same policy grows from RBAC into ABAC without changing shape.


## Used by

<p align="center">
  <img src="https://cerbos.dev/assets/logos/readme_logos.png" alt="Cerbos"/>
</p>


Teams of all sizes run Cerbos in production. Read how in our [success stories](https://www.cerbos.dev/customers?utm_campaign=brand_cerbos&utm_source=github).


## Installation

* [Container](https://docs.cerbos.dev/cerbos/latest/installation/container.html?utm_campaign=brand_cerbos&utm_source=github)
* [Binary/OS packages](https://docs.cerbos.dev/cerbos/latest/installation/binary.html?utm_campaign=brand_cerbos&utm_source=github)
* [Helm Chart](https://docs.cerbos.dev/cerbos/latest/installation/helm.html?utm_campaign=brand_cerbos&utm_source=github)


## Running the PDP in production

The engine (Cerbos PDP) is stateless, so you can run as many instances as you need with no coordination between them and no shared database. On Kubernetes that is usually a sidecar next to each application pod, or a DaemonSet on larger clusters where a sidecar per pod is too much overhead. Everywhere else it runs as a standalone service behind a load balancer. See [deployment models](https://docs.cerbos.dev/cerbos/latest/deployment/index.html?utm_campaign=brand_cerbos&utm_source=github).

Git is the preferred way to store policies in production. Each instance polls the store on its own schedule, so for a short window during a rollout different instances can be serving different versions of a policy. See [storage drivers](https://docs.cerbos.dev/cerbos/latest/configuration/storage.html?utm_campaign=brand_cerbos&utm_source=github).

Audit and decision logging is off by default, so turn it on before you need it. The local backend keeps a store on disk you can query with `cerbosctl`, the file backend writes newline-delimited JSON you can feed into your existing log pipeline, and there is a Kafka backend if that is where your observability already lives. See [audit configuration](https://docs.cerbos.dev/cerbos/latest/configuration/audit.html?utm_campaign=brand_cerbos&utm_source=github).

That is the shape of running the engine yourself. Here is what the [rest of the platform](https://www.cerbos.dev/how-it-works?utm_campaign=brand_cerbos&utm_source=github) changes:

|  | Cerbos PDP (This repo) | Full Cerbos platform |
| :---- | :---- | :---- |
| **Policy changes** | You wire the tests into CI and roll the change out yourself | Tests run on every commit and a failing test blocks the rollout |
| **Instances in sync** | Each instance pulls policy from your own git repo or bucket, on a schedule you set up | Same policy on every running instance within seconds, no redeploy |
| **Decision logs** | Each instance writes its own locally until you build something to collect them | Searchable in one place and traceable to the exact policy version |
| **Data for a decision** | Each service fetches the user and resource details before it can ask | Your app sends a user ID and the rest is fetched from your identity provider or database |

Everything you build on the engine keeps working. Moving to the platform is a configuration change, not a rewrite. The engine is supported by the community Slack, and commercial support comes with the platform. [Start with the platform for free](https://hub.cerbos.cloud/?utm_campaign=brand_cerbos&utm_source=github) or [see pricing](https://www.cerbos.dev/pricing?utm_campaign=brand_cerbos&utm_source=github).

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

## SDKs and adapters

We maintain all of these, and they all talk to the same [Cerbos API](https://docs.cerbos.dev/cerbos/latest/api/index.html?utm_campaign=brand_cerbos&utm_source=github).

**Client SDKs** call the PDP from your application and handle the connection and serialization for you. [Go](https://github.com/cerbos/cerbos-sdk-go), [Java](https://github.com/cerbos/cerbos-sdk-java), [JavaScript](https://github.com/cerbos/cerbos-sdk-javascript), [.NET](https://github.com/cerbos/cerbos-sdk-net), [PHP](https://github.com/cerbos/cerbos-sdk-php), [Python](https://github.com/cerbos/cerbos-sdk-python), [Ruby](https://github.com/cerbos/cerbos-sdk-ruby), [Rust](https://github.com/cerbos/cerbos-sdk-rust), [Laravel](https://github.com/cerbos/cerbos-sdk-laravel).

**Query plan adapters** take the filter the PDP returns from `PlanResources` and turn it into a query for your ORM or database, so a list endpoint only fetches the rows a user is allowed to see.

* JavaScript. [Prisma](https://github.com/cerbos/query-plan-adapters/tree/main/prisma), [Drizzle](https://github.com/cerbos/query-plan-adapters/tree/main/drizzle), [Mongoose](https://github.com/cerbos/query-plan-adapters/tree/main/mongoose), [Convex](https://github.com/cerbos/query-plan-adapters/tree/main/convex)  
* Python. [SQLAlchemy](https://github.com/cerbos/query-plan-adapters/tree/main/sqlalchemy), [LangChain with ChromaDB](https://github.com/cerbos/query-plan-adapters/tree/main/langchain-chromadb)  
* Go. [ent](https://github.com/cerbos/query-plan-adapters/tree/main/ent), [pgx](https://github.com/cerbos/query-plan-adapters/tree/main/pgx)  
* Java. [Spring Data](https://github.com/cerbos/query-plan-adapters/tree/main/spring-data), [Elasticsearch](https://github.com/cerbos/query-plan-adapters/tree/main/elasticsearch-java)  
* Ruby. [ActiveRecord](https://github.com/cerbos/query-plan-adapters/tree/main/activerecord)

## Telemetry

We collect anonymous usage data to help us improve the product. You can opt out by setting the `CERBOS_NO_TELEMETRY=1` environment variable. For more information about what data we collect and other ways to opt out, see the [telemetry documentation](https://docs.cerbos.dev/cerbos/latest/configuration/telemetry.html?utm_campaign=brand_cerbos&utm_source=github).

## Join the community on Slack

<a href="http://go.cerbos.io/slack"><img src="https://i.ibb.co/GxJfc1Q/cerbos-slack-btn.png" width="200"></a>

## Links
* [Slack community](https://community.cerbos.dev/?utm_campaign=brand_cerbos&utm_source=github) for questions and help from the team and other users  
* [Newsletter](https://cerbos.dev/subscribe?utm_campaign=brand_cerbos&utm_source=github) for product updates once a month  
* [Tutorial](https://docs.cerbos.dev/cerbos/latest/tutorial/00_intro.html?utm_campaign=brand_cerbos&utm_source=github) for building a working example from scratch  
* [Demo repositories](https://github.com/cerbos) showing Cerbos in Go, Python, TypeScript, NestJS and Laravel  
* [Contribution guidelines](https://github.com/cerbos/cerbos/blob/main/CONTRIBUTING.md) for sending us a pull request

## License

Cerbos is licensed under the Apache License 2.0 - see the [LICENSE](https://github.com/cerbos/cerbos/blob/main/LICENSE) file for details.

## Big thank you to all contributors!

<a>
  <img src="https://contributors-img.web.app/image?repo=cerbos/cerbos" alt="Contributors"/>
</a>
