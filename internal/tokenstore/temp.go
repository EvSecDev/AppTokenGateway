package tokenstore

import (
	"os"
	"syscall"
)

// Finds temp directory on the same filesystem as the store path.
func (store *RuntimeStore) findTempDirectory() (err error) {
	info, err := os.Stat(store.storePath)
	if err != nil {
		return
	}
	storeStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	potentialTmpDirs := []string{"/tmp", "/var/tmp"}
	for _, candidate := range potentialTmpDirs {
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		if stat.Dev == storeStat.Dev {
			store.tempDir = candidate
			break
		}
	}
	return
}
