// Package dnshelpers provides small helpers shared between the file
// client and the SOCKS5-proxy client for the per-conn DNS transaction-id
// dispatch used by both their UDP and TCP DNS pools.
package dnshelpers

import "errors"

// ReserveDNSIDLocked allocates a free DNS transaction id for a pending
// channel. It walks `*nextID` forward until it finds an id not already
// in `pending`, registers `ch` for that id, and returns it. Wraps
// uint16 at 1 (skips 0 which is reserved by convention).
//
// Caller must hold the mutex protecting `pending` and `nextID`. Returns
// an error only if the 16-bit id space is fully saturated (>65535
// outstanding queries on the same conn — astronomically unlikely for
// our pool sizes).
func ReserveDNSIDLocked(pending map[uint16]chan []byte, nextID *uint16, ch chan []byte) (uint16, error) {
	for range 65535 {
		*nextID = *nextID + 1
		if *nextID == 0 {
			*nextID = 1
		}
		id := *nextID
		if _, exists := pending[id]; exists {
			continue
		}
		pending[id] = ch
		return id, nil
	}
	return 0, errors.New("dns transaction id space exhausted")
}

// DeletePendingIfOwnedLocked removes a pending registration, but only
// if the slot still belongs to the caller. This guards the race where
// another goroutine (e.g. readLoop closing all pendings on conn death)
// has already cleared our slot — without the ownership check we could
// delete a NEW registration for the same recycled id.
//
// Caller must hold the mutex protecting `pending`.
func DeletePendingIfOwnedLocked(pending map[uint16]chan []byte, id uint16, ch chan []byte) {
	if pending[id] == ch {
		delete(pending, id)
	}
}
