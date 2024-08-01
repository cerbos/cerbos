# E2E Tests


## Requirements

- [kind](https://kind.sigs.k8s.io)
- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
- [Helm](https://helm.sh)
- [Helmfile](https://github.com/helmfile/helmfile)
- [Telepresence](https://www.telepresence.io/docs/latest/install/)

## Running tests

```sh
# Run all tests
./run.sh

# Run a subset of tests
./run.sh ./mysql/...

# Pass arguments
./run.sh ./... -args -run-id=mytest
```

### Common Problems

#### Telepresence timeout

If telepresence exits with `telepresence: error: connector.Connect: failed to start traffic manager: the helm operation timed out`, try increasing the timeout in `~/.config/telepresence/config.yml`.

```sh
$ cat ~/.config/telepresence/config.yml
timeouts:
  helm: 60s
```

### How do I

#### Use an existing K8s cluster

Set `E2E_SKIP_CLUSTER=true`

```sh
E2E_SKIP_CLUSTER=true ./run.sh
```

#### Prevent the cluster and fixtures from being destroyed

Start the script with `E2E_NO_CLEANUP=true`

```sh
E2E_NO_CLEANUP=true ./run.sh
```

#### Test a Cerbos image that is not yet published

By default, the tests use the `ghcr.io/cerbos/cerbos:dev` image. If you have made local changes and want to test them immediately, load the image into Kind manually.


```sh
# Build the Cerbos image
just build

# Load the image into Kind
kind load docker-image ghcr.io/cerbos/cerbos:0.37.0-prerelease-amd64 --name=cerbos-e2e

# Re-run the test with the new image
E2E_SKIP_CLUSTER=true ./run.sh ./git/... -args -cerbos-img-tag=0.37.0-prerelease-amd64
```
