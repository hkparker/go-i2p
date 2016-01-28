package main

import (

  "github.com/bounce-chat/go-i2p/lib/router"
  
  "github.com/golang/glog"
  "flag"
)



func main() {

  flag.Parse()

  glog.Info("parsing i2p router configuration")
  
  glog.Info("starting up i2p router")
  r, err := router.CreateRouter()
  if err == nil {
    r.Run()
  } else {
    glog.Errorf("failed to create i2p router: %s", err)
  }
}
