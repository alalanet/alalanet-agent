//go:build !unix

package main

import "os"

// openNoWait: Windows has no FIFOs in the file system and opens no link without a reparse-point flag the agent does not
// pass; the Lstat and fstat checks around it stand.
func openNoWait(path string) (*os.File, error) { return os.Open(path) }

// openFollowNoWait is openNoWait for a file read through a link (readFollow).
func openFollowNoWait(path string) (*os.File, error) { return os.Open(path) }

// adminOwned is not checked on Windows (round 4, S4): C:\Program Files is writable only by administrators by default,
// and reading its ACL needs code the agent does not carry yet; the ADR says so.
func adminOwned(string) error { return nil }
