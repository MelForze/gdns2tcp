package main

import "testing"

func TestReserveDNSIDLockedSkipsPendingID(t *testing.T) {
	existing := make(chan []byte, 1)
	ch := make(chan []byte, 1)
	nextID := uint16(41)
	pending := map[uint16]chan []byte{42: existing}

	id, err := reserveDNSIDLocked(pending, &nextID, ch)
	if err != nil {
		t.Fatal(err)
	}
	if id != 43 {
		t.Fatalf("reserved id=%d, want 43", id)
	}
	if pending[42] != existing {
		t.Fatal("existing pending id was overwritten")
	}
	deletePendingIfOwnedLocked(pending, 42, ch)
	if pending[42] != existing {
		t.Fatal("deletePendingIfOwnedLocked removed a channel it did not own")
	}
	deletePendingIfOwnedLocked(pending, 43, ch)
	if _, ok := pending[43]; ok {
		t.Fatal("owned pending id was not removed")
	}
}
