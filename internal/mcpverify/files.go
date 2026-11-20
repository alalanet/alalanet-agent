package mcpverify

import (
	"os"

	"github.com/alalanet/alalanet-agent/internal/filelock"
)

// openRegular and lregular: filelock's (a FIFO, a device or a folder is not read; review r3, P3-1 and P3-3).
func openRegular(path string) (*os.File, os.FileInfo, error) { return filelock.OpenRegular(path) }

func lregular(path string) bool { return filelock.Regular(path) }
