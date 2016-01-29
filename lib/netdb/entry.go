package netdb

import (
	"io"
	"path/filepath"
)

type Entry struct {
	fname string
}

func (e *Entry) FilePath(n StdNetDB) (str string) {
	return filepath.Join(string(n), e.fname)
}

func (e *Entry) WriteTo(w io.Writer) (err error) {
	return
}
