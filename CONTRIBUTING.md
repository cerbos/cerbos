Contributing to Cerbos
======================

Thank you for your interest in Cerbos. We welcome contributions from the community. Please note that we have a [code of conduct](CODE_OF_CONDUCT.md) that must be followed when interacting with this project. In addition, please read the guidelines below to ensure that your contributions have a better chance of being accepted.

- [Submitting pull requests](#submitting-pull-requests)
    - [Code changes](#submitting-pull-requests-for-code-changes)
    - [Documentation changes](#submitting-pull-requests-for-documentation-changes)
- [Developing Cerbos](#developing-cerbos)
- [Getting help](#getting-help)

Submitting pull requests
------------------------

- Before submitting a pull request, please [raise an issue](https://github.com/cerbos/cerbos/issues) in the GitHub repository and provide information about the problem you are trying to fix and how you plan to address it. Include as much detail as possible to make it easier for others to understand your thought process.
- Wait for the project maintainers and other community members to respond to your proposal and clearly agree on a course of action.
- Create your patch, constraining yourself to what was agreed on the issue. If previously unforeseen problems arise and you have to make significant changes to an area that wasn’t discussed in the issue, make sure to go back to the issue to discuss the new circumstances and get buy-in from the people who are involved.
- Run the pre-commit checks that are appropriate for the kind of change. (See below for details.)
- Submit your pull request. Use the [closing keywords](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword) to link the PR to the original issue. Make sure to use the appropriate prefix to the pull request title:
  - `bug:` Bug fix
  - `chore:` General maintenance work
      - `chore(ci):` CI related work
      - `chore(deps):` Dependency updates
      - `chore(refactor):` Refactoring
      - `chore(release):` Release related work
      - `chore(test):` Tests
   - `docs:` Documentation changes
   - `enhancement:` Enhancements to existing features
   - `feature:` New feature
- At least one approval from a maintainer is required to merge the pull request.


### Submitting pull requests for code changes

- Write idiomatic Go. [Effective Go](https://golang.org/doc/effective_go) is the canonical source while the [Uber style guide](https://github.com/uber-go/guide/blob/master/style.md) contains a lot of good advice as well.
- Make sure each source file contains the appropriate licence header:
    ```
    Copyright 2021 Zenauth Ltd.
    SPDX-License-Identifier: Apache-2.0
    ```
- Add tests to cover the functionality you are adding or modifying.
- Add new documentation or update existing content to ensure that the documentation stays consistent with the change you are introducing. See [below](#submitting-pull-requests-for-documentation-changes) for tips on writing documentation.
- Avoid introducing new dependencies if possible. All dependencies must have an appropriate open source licence (Apache-2.0, BSD, MIT).
- Make sure your code is `gofmt`ed. Run `make lint` and fix any warnings produced by the linter. 
- Sign-off your commits to provide a [DCO](https://developercertificate.org). You can do this by adding the `-s` flag to your `git commit` command.
    ```sh
    git commit -s -m 'bug: Fix for bug X'
    ```

### Submitting pull requests for documentation changes

- We use [Asciidoctor](https://asciidoctor.org/docs/asciidoc-writers-guide/) to write documentation. Please note that some AsciiDoctor features might not be available in [Antora](https://docs.antora.org/antora/2.3/), the static site generation software we use.
- Use simple, [inclusive language](https://developers.google.com/style/inclusive-documentation). Also refer to the [Microsoft Style Guide](https://docs.microsoft.com/en-us/style-guide/welcome/) for general advice on writing good documentation.
- Do not add third-party content in-line without attribution. Use links where possible.
- Ensure that any binary assets (images, videos, etc.) are added to [Git LFS](https://github.com/git-lfs/git-lfs/tree/main/docs).
- Sign-off your commits to provide a [DCO](https://developercertificate.org). You can do this by adding the `-s` flag to your `git commit` command.
    ```sh
    git commit -s -m 'bug: Fix for bug X'
    ```

Developing Cerbos
-----------------

Cerbos is developed using the [Go programming language](https://golang.org). We currently require Go 1.16.x for development.

The `Makefile` automatically installs required build tools using the versions defined in `tools/go.mod`. Run `make clean-tools` to clear the cache and force the installation of new versions.

Useful `make` targets:

- `make build`: Compile, test and build the Cerbos binaries and container. Binaries will be output to the `dist` directory. The container name is `ghcr.io/cerbos/cerbos:latest`.
- `make pre-commit`: Run tests, lint, and generate code and documentation. Run this before submitting a PR to make sure your code is ready to submit.
- `make dev-server`: Start a Cerbos server 
- `make docs`: Generate docs and preview in browser.


Getting Help
------------

- [Read the documentation](https://docs.cerbos.dev)
- Post a question in the [discussion forum](https://github.com/cerbos/cerbos/discussions)
- Join our [Slack community](http://go.cerbos.io/slack)
- Email us at help@cerbos.dev
- Visit our website at https://cerbos.dev
