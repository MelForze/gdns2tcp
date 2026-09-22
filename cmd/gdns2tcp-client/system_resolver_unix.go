//go:build !windows

package main

import (
	"errors"
	"net"
	"os"
	"strings"
)

func systemResolverAddress() (string, error) {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" && net.ParseIP(fields[1]) != nil {
			return fields[1], nil
		}
	}
	return "", errors.New("no nameserver entry in /etc/resolv.conf")
}
