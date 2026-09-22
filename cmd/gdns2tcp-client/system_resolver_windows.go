//go:build windows

package main

import (
	"errors"
	"fmt"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

func systemResolverAddress() (string, error) {
	var size uint32 = 15 * 1024
	for attempt := 0; attempt < 3; attempt++ {
		buffer := make([]byte, size)
		adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, adapters, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("read Windows adapter DNS configuration: %w", err)
		}

		var ipv6 string
		for adapter := adapters; adapter != nil; adapter = adapter.Next {
			if adapter.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
				ip := server.Address.IP()
				if ip == nil || ip.IsUnspecified() {
					continue
				}
				if ip.To4() != nil {
					return ip.String(), nil
				}
				if ipv6 == "" && ip.To16() != nil {
					addr := ip.String()
					if server.Address.Sockaddr != nil {
						raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(server.Address.Sockaddr))
						if raw.Family == windows.AF_INET6 && raw.Scope_id != 0 && ip.IsLinkLocalUnicast() {
							addr += "%" + strconv.FormatUint(uint64(raw.Scope_id), 10)
						}
					}
					ipv6 = addr
				}
			}
		}
		if ipv6 != "" {
			return ipv6, nil
		}
		return "", errors.New("no DNS server on an active Windows network adapter")
	}
	return "", errors.New("Windows adapter DNS configuration kept changing size")
}
