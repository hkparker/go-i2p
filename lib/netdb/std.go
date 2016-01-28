package netdb

import (
  log "github.com/golang/glog"
  "github.com/bounce-chat/go-i2p/lib/common"
  "io"
  "os"
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

func (db StdNetDB) SaveEntry(e *Entry) (err error) {
  var f io.WriteCloser 
  f, err = os.OpenFile(e.FilePath(db), os.O_WRONLY, 0600)
  if err == nil {
    err = e.WriteTo(f)
    if err != nil {
      log.Errorf("failed to write netdb entry: %s", err.Error())
    }
    f.Close()
  } else {
    log.Errorf("failed to save netdb entry: %s", err.Error())
  }
  return
}


// reseed if we have less than minRouters known routers
// returns error if reseed failed
func (db StdNetDB) Reseed(minRouters int) (err error) {
  current := db.KnownPeerCount()
  if current <= minRouters {
    // we need to reseed
    rs := GetRandomReseed()
    log.Infof("Reseeding from %s", rs)
    chnl := make(chan *Entry)
    // receive entries from reseed
    go func(c chan *Entry) {
      count := 0
      for {
        e, ok := <- c
        if ok {
          // got an entry
          // save it to our netdb
          err := db.SaveEntry(e)
          if err == nil {
            count ++
          }
        }
      }
    }(chnl) // call
    err = rs.Reseed(chnl)
  }
  return
}

// ensure that the network database exists and is seeded with a minimum number of routers
func (db StdNetDB) Ensure(minRouters int) (err error) {
  if ! db.Exists() {
    err = db.Create()
  }
  if err == nil {
    // database directory ensured
    // try to reseed
    err = db.Reseed(minRouters)
  }
  return
}

// create base network database directory
func (db StdNetDB) Create() (err error) {
  log.Infof("Create network database in %s", db.Path())
  err = os.Mkdir(db.Path(), 0600)
  return
}
