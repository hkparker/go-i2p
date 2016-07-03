package main

import (
	"github.com/hkparker/go-i2p/lib/router"

	"flag"
	log "github.com/golang/glog"
)

func main() {

	flag.Parse()

	log.Info("parsing i2p router configuration")

	log.Info("starting up i2p router")
	r, err := router.CreateRouter()
	if err == nil {
		r.Run()
	} else {
		log.Errorf("failed to create i2p router: %s", err)
	}
}
