//go:build !windows

package main

import (
	"errors"
	"os"
	"strings"
)

func systemResolverAddress() (string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return fields[1], nil
		}
	}
	return "", errors.New("no nameserver line in /etc/resolv.conf")
}
