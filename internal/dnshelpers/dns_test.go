package dnshelpers

import "testing"

func TestReserveDNSIDLockedSkipsPendingID(t *testing.T) {
	existing := make(chan []byte, 1)
	ch := make(chan []byte, 1)
	nextID := uint16(41)
	pending := map[uint16]chan []byte{42: existing}

	id, err := ReserveDNSIDLocked(pending, &nextID, ch)
	if err != nil {
		t.Fatal(err)
	}
	if id != 43 {
		t.Fatalf("reserved id=%d, want 43", id)
	}
	if pending[42] != existing {
		t.Fatal("existing pending id was overwritten")
	}
}

func TestReserveDNSIDLockedWrapsAroundZero(t *testing.T) {
	ch := make(chan []byte, 1)
	nextID := uint16(65535)
	pending := map[uint16]chan []byte{}

	id, err := ReserveDNSIDLocked(pending, &nextID, ch)
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Fatalf("wrap: got id=%d, want 1 (skip zero)", id)
	}
}

func TestReserveDNSIDLockedExhausted(t *testing.T) {
	ch := make(chan []byte, 1)
	nextID := uint16(0)
	pending := make(map[uint16]chan []byte, 65535)
	for i := uint16(1); i != 0; i++ {
		pending[i] = ch
	}
	if _, err := ReserveDNSIDLocked(pending, &nextID, ch); err == nil {
		t.Fatal("expected exhaustion error when all ids in use")
	}
}

func TestDeletePendingIfOwnedLocked(t *testing.T) {
	ch := make(chan []byte, 1)
	other := make(chan []byte, 1)
	pending := map[uint16]chan []byte{
		1: ch,
		2: other,
	}

	DeletePendingIfOwnedLocked(pending, 1, ch)
	if _, ok := pending[1]; ok {
		t.Fatal("owned entry was not removed")
	}
	DeletePendingIfOwnedLocked(pending, 2, ch)
	if pending[2] != other {
		t.Fatal("un-owned entry was removed")
	}
	DeletePendingIfOwnedLocked(pending, 99, ch) // absent key — no-op
}
