package netdb

import (
  "github.com/golang/glog"
  "github.com/majestrate/goi2p/lib/common"
  "os"
  "time"
)

// standard network database implementation
type StdNetDB string


// get netdb path
func (db StdNetDB) Path() string {
  return string(db)
}

//
// return how many routers we know about in our network database
//
func (db StdNetDB) KnownPeerCount() (routers int) {
  return
}

// return true if the network db directory exists and is writable
func (db StdNetDB) Exists() bool {
  return common.FileExists(db.Path())
}

// create base network database directory
func (db StdNetDB) Create() (err error) {
  glog.Infof("Create network database in %s", db.Path())
  err = os.Mkdir(db.Path(), 0600)
  return
}
