//go:build linux || darwin

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type resumeFileLock struct {
	file *os.File
}

func acquireResumeFileLock(path string, nonBlocking bool) (*resumeFileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	op := unix.LOCK_EX
	if nonBlocking {
		op |= unix.LOCK_NB
	}
	if err := unix.Flock(int(f.Fd()), op); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, os.ErrDeadlineExceeded
		}
		return nil, err
	}
	return &resumeFileLock{file: f}, nil
}

func (l *resumeFileLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	return closeErr
}
