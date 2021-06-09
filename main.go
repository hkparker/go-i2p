package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/router"
)

func main() {

	log.Info("parsing i2p router configuration")

	log.Info("starting up i2p router")
	r, err := router.CreateRouter()
	if err == nil {
		r.Run()
	} else {
		log.Errorf("failed to create i2p router: %s", err)
	}
}
