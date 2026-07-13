//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
	"time"
)

// The released file-client matrix is Linux/macOS. Keep other builds usable
// with a portable exclusive-create fallback; Unix builds use advisory locks,
// which are automatically released after a crash.
type resumeFileLock struct {
	path string
	file *os.File
}

func acquireResumeFileLock(path string, nonBlocking bool) (*resumeFileLock, error) {
	for {
		f, err := os.OpenFile(path+".owner", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			return &resumeFileLock{path: path + ".owner", file: f}, nil
		}
		if !errors.Is(err, os.ErrExist) || nonBlocking {
			return nil, err
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
