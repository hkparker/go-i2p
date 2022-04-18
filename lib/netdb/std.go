package netdb

import (
	"bytes"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/hkparker/go-i2p/lib/bootstrap"
	"github.com/hkparker/go-i2p/lib/common"
	"github.com/hkparker/go-i2p/lib/common/base64"
	"io"
	"os"
	"path/filepath"
)

// standard network database implementation using local filesystem skiplist
type StdNetDB string

func (db StdNetDB) GetRouterInfo(hash common.Hash) (chnl chan common.RouterInfo) {
	fname := db.SkiplistFile(hash)
	f, err := os.Open(fname)
	if err != nil {
		return nil
	}
	buff := new(bytes.Buffer)
	_, err = io.Copy(buff, f)
	f.Close()
	chnl = make(chan common.RouterInfo)
	chnl <- common.RouterInfo(buff.Bytes())
	return
}

// get the skiplist file that a RouterInfo with this hash would go in
func (db StdNetDB) SkiplistFile(hash common.Hash) (fpath string) {
	fname := base64.EncodeToString(hash[:])
	fpath = filepath.Join(db.Path(), fmt.Sprintf("r%c", fname[0]), fmt.Sprintf("routerInfo-%s.dat", fname))
	return
}

// get netdb path
func (db StdNetDB) Path() string {
	return string(db)
}

//
// return how many routers we know about in our network database
//
func (db StdNetDB) Size() (routers int) {
	return
}

// return true if the network db directory exists and is writable
func (db StdNetDB) Exists() bool {
	p := db.Path()
	// check root directory
	_, err := os.Stat(p)
	if err == nil {
		// check subdirectories for skiplist
		for _, c := range base64.Alphabet {
			if _, err = os.Stat(filepath.Join(p, fmt.Sprintf("r%c", c))); err != nil {
				return false
			}
		}
	}
	return err == nil
}

func (db StdNetDB) SaveEntry(e *Entry) (err error) {
	var f io.WriteCloser
	var h common.Hash
	h, err = e.ri.IdentHash()
	if err == nil {
		f, err = os.OpenFile(db.SkiplistFile(h), os.O_WRONLY|os.O_CREATE, 0700)
		if err == nil {
			err = e.WriteTo(f)
			f.Close()
		}
	}
	if err != nil {
		log.Errorf("failed to save netdb entry: %s", err.Error())
	}
	return
}

// reseed if we have less than minRouters known routers
// returns error if reseed failed
func (db StdNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) (err error) {
	return
}

// ensure that the network database exists
func (db StdNetDB) Ensure() (err error) {
	if !db.Exists() {
		err = db.Create()
	}
	return
}

// create base network database directory
func (db StdNetDB) Create() (err error) {
	mode := os.FileMode(0700)
	p := db.Path()
	log.Infof("Create network database in %s", p)

	// create root for skiplist
	err = os.Mkdir(p, mode)
	if err == nil {
		// create all subdirectories for skiplist
		for _, c := range base64.Alphabet {
			err = os.Mkdir(filepath.Join(p, fmt.Sprintf("r%c", c)), mode)
			if err != nil {
				return
			}
		}
	}
	return
}
