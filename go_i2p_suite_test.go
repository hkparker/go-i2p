package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGoI2p(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "GoI2p Suite")
}
