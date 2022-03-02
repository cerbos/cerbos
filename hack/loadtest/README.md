# Load test scripts

Requires [K6](https://k6.io/docs/) and docker-compose.
Requires `cerbosctl` binary to be in the PATH.

## Usage

The following environment variables are used to determine the test parameters.

- `DURATION`: How long to run the tests for. Default `120s`.
- `ITERATIONS`: Number of requests to send using MAX_VUS.
- `MAX_VUS`: Maximum virtual users. Default `100`.
- `MIN_VUS`: Minimum virtual users. Default `25`.
- `NUM_POLICIES`: Number of policies. Default `1000`.
- `REQ_COUNT`: Number of requests on disk. Default `1000`.
- `REQ_KIND`: Kind (prefix) of the requests to use for the test. Default `crs_req01`.
- `RPS`: Request rate to sustain per virtual user. Default `200`.
- `STORE`: Store to use. Default `disk`.
- `SERVER`: Cerbos server host address. Default `localhost:3593`.
- `USERNAME`: Cerbos Admin API username. Default `cerbos`.
- `PASSWORD`: Cerbos Admin API password. Default `cerbosAdmin`.

Start the Cerbos instance

```sh
NUM_POLICIES=1000 ./loadtest.sh -u
```

In another shell: generate test data and run the test

```sh
NUM_POLICIES=1000 RPS=250 ./loadtest.sh -e
```

Stop the Cerbos instance after the test.

```sh
./loadtest.sh -d
```
