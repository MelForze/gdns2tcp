//go:build !linux && !darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"time"
)

const lockStaleAge = 5 * time.Minute

// The released file-client matrix is Linux/macOS. Keep other builds usable
// with a portable exclusive-create fallback; Unix builds use advisory locks,
// which are automatically released after a crash.
type resumeFileLock struct {
	path string
	file *os.File
}

func acquireResumeFileLock(path string, nonBlocking bool) (*resumeFileLock, error) {
	lockPath := path + ".owner"
	const maxWait = 30 * time.Second
	deadline := time.Now().Add(maxWait)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			return &resumeFileLock{path: lockPath, file: f}, nil
		}
		if !errors.Is(err, os.ErrExist) || nonBlocking {
			return nil, err
		}
		// If the lock file is older than lockStaleAge, the holder likely
		// crashed without cleaning up. Remove the stale file and retry.
		if info, statErr := os.Stat(lockPath); statErr == nil {
			if time.Since(info.ModTime()) > lockStaleAge {
				_ = os.Remove(lockPath)
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for resume lock %s", lockPath)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (l *resumeFileLock) release() error {
	if l == nil {
		return nil
	}
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	return os.Remove(l.path)
}
