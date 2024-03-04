# cerbosctl

[![npm](https://img.shields.io/npm/v/cerbosctl?style=flat-square)](https://www.npmjs.com/package/cerbosctl)

[Cerbos](https://cerbos.dev) helps you super-charge your authorization implementation by writing context-aware access control policies for your application resources.
Author access rules using an intuitive YAML configuration language, use your Git-ops infrastructure to test and deploy them, and make simple API requests to the Cerbos policy decision point (PDP) server to evaluate the policies and make dynamic access decisions.

This package provides the [`cerbosctl`](https://docs.cerbos.dev/cerbos/latest/cli/cerbosctl) binary in an npm package.
To interact with the Cerbos PDP from your application, you can use [the SDK](https://github.com/cerbos/cerbos-sdk-javascript).

## Installation

```console
$ npm install cerbosctl
```

Note that this package relies on platform-specific optional dependencies, so make sure you don't omit these when installing dependencies (for example, don't pass the `--no-optional` flag to `npm`).

### Supported platforms

| OS | Architecture |
|---|---|
| darwin | arm64 |
| darwin | x64 |
| linux | arm64 |
| linux | x64 |

## Further reading

- [CLI reference](https://docs.cerbos.dev/cerbos/latest/cli/cerbosctl)
- [Cerbos documentation](https://docs.cerbos.dev)

## Get help

- [Join the Cerbos community on Slack](http://go.cerbos.io/slack)
- [Email us at help@cerbos.dev](mailto:help@cerbos.dev)
