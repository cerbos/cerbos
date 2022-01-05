// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cerbos/cerbos/e2e/common"
)

var _ = Describe("Postgres", func() {
	It("Should be healthy", func() {
		healthURL := common.TestConf.HealthURL()
		Eventually(func(g Gomega) {
			resp, err := http.Get(healthURL)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(resp).To(HaveHTTPStatus(http.StatusOK))
		}).Should(Succeed())
	})
})
