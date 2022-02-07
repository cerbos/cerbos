// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// PROTOCOL: HTTP
// ENDPOINT: /api/check

import { SharedArray } from 'k6/data';
import http from 'k6/http';
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.1.0/index.js';

export const options = {
    vus: 300,
    duration: '60s',
};

const authHeader = "Basic Y2VyYm9zOmNlcmJvc0FkbWlu"
const baseDir = "./gen"
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
    const idx = randomIntBetween(0, requests.length-1);
    http.post(url, requests[idx], {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
        },
    });
}
