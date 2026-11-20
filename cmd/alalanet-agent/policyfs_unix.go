//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// openNoWait opens a file for reading without following a link (O_NOFOLLOW) and without waiting for a FIFO's writer
// (O_NONBLOCK); reads of a regular file are not affected by O_NONBLOCK (round 4, S1).
func openNoWait(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
}

// openFollowNoWait is openNoWait for a file read through a link (readFollow): it follows the link, and still never
// waits for a FIFO's writer.
func openFollowNoWait(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
}

// adminOwned: the organisation's file and the folder it is in belong to root and nobody else can write them — else
// the file is not the administrator's word (round 4, S4). Where the agent runs as root (a container, a devcontainer)
// this proves nothing more, and the file is taken as is.
func adminOwned(path string) error { return adminOwnedWith(os.Stat, path) }

// adminOwnedWith is adminOwned with the stat it uses (tests give one: a root-owned, group-writable file cannot be made
// without root).
func adminOwnedWith(stat func(string) (os.FileInfo, error), path string) error {
	for _, p := range []string{path, filepath.Dir(path)} {
		fi, err := stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("its owner cannot be read")
		}
		switch {
		case st.Uid != 0:
			return errors.New(p + " is not owned by root")
		case fi.Mode().Perm()&0o022 != 0:
			return errors.New(p + " can be written by others than root")
		}
	}
	return nil
}
