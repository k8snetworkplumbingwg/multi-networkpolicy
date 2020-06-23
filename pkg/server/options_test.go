package server

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("server option", func() {
	It("Check container runtime option valid case", func() {
		opt := NewOptions()
		opt.containerRuntimeStr = "docker"
		Expect(opt.Validate()).To(BeNil())
		opt.containerRuntimeStr = "DOCKER"
		Expect(opt.Validate()).To(BeNil())
		opt.containerRuntimeStr = "crio"
		Expect(opt.Validate()).To(BeNil())
		opt.containerRuntimeStr = "CRIO"
		Expect(opt.Validate()).To(BeNil())
	})
	It("Check container runtime option invalid case", func() {
		opt := NewOptions()
		opt.containerRuntimeStr = "Foobar"
		Expect(opt.Validate()).To(MatchError("Invalid container-runtime option Foobar (possible value: \"docker\", \"crio\""))
	})
})
