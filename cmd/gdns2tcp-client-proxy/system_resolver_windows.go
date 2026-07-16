//go:build windows

package main

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemResolverAddress reads the active adapters through IP Helper instead
// of assuming a Unix resolv.conf path. IPv4 is preferred because it works in
// networks where the adapter has an IPv6 DNS address but no usable IPv6
// route to that resolver.
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
					var scopeID uint32
					if server.Address.Sockaddr != nil {
						raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(server.Address.Sockaddr))
						if raw.Family == windows.AF_INET6 {
							scopeID = raw.Scope_id
						}
					}
					ipv6 = formatResolverAddress(ip, scopeID)
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
