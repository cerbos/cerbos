// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// PROTOCOL: gRPC
// SERVICE: cerbos.svc.v1.CerbosService/CheckResources

import { SharedArray } from 'k6/data';
import grpc from 'k6/net/grpc';
import { randomSeed, check } from 'k6';
import { randomItem } from 'https://jslib.k6.io/k6-utils/1.1.0/index.js';

randomSeed(999333666);

const client = new grpc.Client();
let connected = false;

export const options = {
    scenarios: {
        constant_rps: {
            executor: 'constant-arrival-rate',
            rate: __ENV.RPS,
            duration: `${__ENV.DURATION_SECS}s`,
            preAllocatedVUs: __ENV.MIN_VUS,
            maxVUs: __ENV.MAX_VUS,
            startTime: "0s",
        },
        shared_iters: {
            executor: 'shared-iterations',
            vus: __ENV.MAX_VUS,
            iterations: __ENV.ITERATIONS,
            startTime: `${__ENV.DURATION_SECS}s`,
        },
    },
    thresholds: {
        grpc_req_duration: ['p(95)<300'], // 95% of requests should be below 300ms
        checks: ['rate>0.99'], // >99% of checks should pass
    },
};

const requestsDir = `${__ENV.WORK_DIR}/requests`

const fileName = (prefix, num) => `${requestsDir}/${prefix}_${num.toString().padStart(5, 0)}.json`;

const requests = new SharedArray('requests', function () {
    const reqKind = __ENV.REQ_KIND
    const reqCount = __ENV.REQ_COUNT
    let reqs = []

    for (let i = 0; i < reqCount; i++) {
        const f = fileName(reqKind, i);
        const r = JSON.parse(open(f));
        reqs.push(r)
    }

    return reqs
});

// containsExpected checks that all fields in `expected` exist in `actual` with
// matching values. Extra fields in `actual` (e.g. protobuf zero-value defaults)
// are ignored.
function containsExpected(actual, expected) {
    if (Array.isArray(expected) && Array.isArray(actual)) {
        if (expected.length !== actual.length) return false;
        for (let i = 0; i < expected.length; i++) {
            if (!containsExpected(actual[i], expected[i])) return false;
        }
        return true;
    }
    if (expected != null && typeof expected === 'object' &&
        actual != null && typeof actual === 'object') {
        for (const key of Object.keys(expected)) {
            if (!(key in actual)) return false;
            if (!containsExpected(actual[key], expected[key])) return false;
        }
        return true;
    }
    return actual === expected;
}

export default function () {
    if (!connected) {
        client.connect(__ENV.SERVER, { plaintext: true, reflect: true });
        connected = true;
    }
    const req = randomItem(requests);
    const res = client.invoke(
        'cerbos.svc.v1.CerbosService/CheckResources',
        req.request,
    );

    check(res, {
        'status is OK': (r) => r.status === grpc.StatusOK,
        'response matches expected': (r) => containsExpected(r.message, req.wantResponse),
    });
}
