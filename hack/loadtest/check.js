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

// https://dmitripavlutin.com/how-to-compare-objects-in-javascript/
function isObject(object) {
    return object != null && typeof object === 'object';
}

// https://dmitripavlutin.com/how-to-compare-objects-in-javascript/
function deepEqual(object1, object2) {
    const keys1 = Object.keys(object1);
    const keys2 = Object.keys(object2);
    if (keys1.length !== keys2.length) {
        return false;
    }
    for (const key of keys1) {
        const val1 = object1[key];
        const val2 = object2[key];
        const areObjects = isObject(val1) && isObject(val2);
        if (
            areObjects && !deepEqual(val1, val2) ||
            !areObjects && val1 !== val2
        ) {
            return false;
        }
    }
    return true;
}

export default function () {
    client.connect(__ENV.SERVER, { plaintext: true, reflect: true });
    const req = randomItem(requests);
    const res = client.invoke(
        'cerbos.svc.v1.CerbosService/CheckResources',
        req.request,
    );

    check(res, {
        'status is OK': (r) => r.status === grpc.StatusOK,
        'response matches expected': (r) => deepEqual(r.message, req.wantResponse),
    });
    client.close();
}
