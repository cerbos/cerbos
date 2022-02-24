# Load test scripts

Requires [K6](https://k6.io/docs/) and docker-compose.

## Usage

The following environment variables are used to determine the test parameters.

- `DURATION`: How long to run the tests for. Default 120s.
- `MAX_VUS`: Maximum virtual users. Default 100.
- `MIN_VUS`: Minimum virtual users. Default 25.
- `NUM_POLICIES`: Number of policies. Default 1000.
- `RPS`: Request rate to sustain per virtual user. Default 200.
- `STORE`: Store to use. Default disk.

Start the Cerbos instance

```sh
./loadtest.sh -u
```

In another shell: generate test data and run the test

```sh
NUM_POLICIES=1000 RPS=250 ./loadtest.sh -e
```

Stop the Cerbos instance after the test.

```sh
./loadtest.sh -d
```
