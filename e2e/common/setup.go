// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"net/http"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

func SBSDeploy() []byte {
	env := TestConf.Environ()

	cmd := exec.Command("helmfile", "sync")
	cmd.Env = env
	runCmd(cmd)

	DeferCleanup(func() {
		cmd := exec.Command("helmfile", "destroy")
		cmd.Env = env
		runCmd(cmd)
	})

	healthURL := TestConf.HealthURL()
	Eventually(checkCerbosIsUp(healthURL)).Should(Succeed())

	return nil
}

func runCmd(cmd *exec.Cmd) {
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session).WithTimeout(TestConf.DeployTimeout).Should(gexec.Exit(0))
}

func checkCerbosIsUp(healthURL string) func(Gomega) {
	return func(g Gomega) {
		resp, err := http.Get(healthURL)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(resp).To(HaveHTTPStatus(http.StatusOK))
	}
}
