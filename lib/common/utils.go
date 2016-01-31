package common

import (
	"os"
)

// check if a file is there and writeable
func FileExists(fname string) (exists bool) {
	_, err := os.Stat(fname)
	if err == nil {
		exists = true
	}
	return
}
