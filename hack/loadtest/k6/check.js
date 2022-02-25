// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// PROTOCOL: HTTP
// ENDPOINT: /api/check

import { SharedArray } from 'k6/data';
import http from 'k6/http';
import { randomSeed, check } from 'k6';
import { randomItem } from 'https://jslib.k6.io/k6-utils/1.1.0/index.js';

export const options = {
    scenarios: {
        constant_load: {
            executor: 'constant-vus',
            vus: __ENV.MIN_VUS,
            duration: __ENV.DURATION,
        },
        constant_rps: {
            executor: 'constant-arrival-rate',
            rate: __ENV.RPS,
            duration: __ENV.DURATION,
            preAllocatedVUs: __ENV.MIN_VUS,
            maxVUs: __ENV.MAX_VUS,
        },
    },
    thresholds: {
        http_req_failed: ['rate<0.01'], // http errors should be less than 1%
        http_req_duration: ['p(95)<300'], // 95% of requests should be below 300ms
    },
};

const authHeader = "Basic Y2VyYm9zOmNlcmJvc0FkbWlu"
const baseDir = "../work/k6"
const idxFile = baseDir + "/request-index.json"
const url = "http://127.0.0.1:3592/api/check"

const requests = new SharedArray('requests', function () {
    const idx = JSON.parse(open(idxFile));
    let reqs = []

    idx.forEach(fileName => {
        const path = baseDir + "/requests/" + fileName
        const r = open(path)
        reqs.push(r)
    })

    return reqs;
});

export default function () {
    randomSeed(999333666);
    const req = randomItem(requests);
    const res = http.post(url, req, {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
        },
    });

    check(res, {
        'status is 200': (r) => r.status === 200,
    });
}
