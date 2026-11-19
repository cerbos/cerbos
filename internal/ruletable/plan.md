# How the query planner combines policy types

This describes how `plan.go` combines the resource policy and the principal policy for a single action. It does not cover how scopes or role policies are combined within a policy type.

As a formula:

```
not(pDeny) AND ( pAllow OR ( not(rDeny) AND rAllow ) )
```

This mirrors the check logic, which evaluates the principal policy first and falls through to the resource policy only when the principal policy has no matching rule. Read left to right, the formula follows the same order. The planner visits the policy types in reverse, resource first, because it builds the formula from the inside out.

The resource policy produces `not(rDeny) AND rAllow`. The principal policy then ORs `pAllow` onto it and wraps everything in `not(pDeny) AND ...`.

- ALLOWs are ORed because a principal ALLOW is a second, higher-priority way in. If it matches, the resource result doesn't matter.
- DENYs are ANDed because a DENY is a veto over everything below it.

A policy type with a DENY but no ALLOW for the action contributes `not(deny) AND false`, which is `false`. It never allows on its own, so a later ALLOW must not be ORed with `not(deny)`.
