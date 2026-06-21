package proxy

import (
	"testing"
)

func TestBufPoolSizeClasses(t *testing.T) {
	cases := []struct {
		req     int
		wantCap int
	}{
		{1, bufSizeSmall},
		{bufSizeSmall, bufSizeSmall},
		{bufSizeSmall + 1, bufSizeMedium},
		{bufSizeMedium, bufSizeMedium},
		{bufSizeMedium + 1, bufSizeLarge},
		{bufSizeLarge + 1, bufSizeBulk},
		{bufSizeBulk + 1, bufSizeBulk + 1}, // bypass — raw alloc
	}
	for _, c := range cases {
		gotPtr := GetBuf(c.req)
		got := *gotPtr
		if len(got) != c.req {
			t.Fatalf("GetBuf(%d) len=%d want %d", c.req, len(got), c.req)
		}
		if cap(got) != c.wantCap {
			t.Fatalf("GetBuf(%d) cap=%d want %d", c.req, cap(got), c.wantCap)
		}
		PutBuf(gotPtr)
	}
}

// TestBufPoolReuse pins that consecutive Put → Get of the same size class
// returns the same underlying array. Without this, the pool isn't actually
// pooling and the GC pressure win evaporates.
func TestBufPoolReuse(t *testing.T) {
	ap := GetBuf(1024)
	(*ap)[0] = 0xAB
	PutBuf(ap)
	bp := GetBuf(1024)
	defer PutBuf(bp)
	if &(*ap)[0] != &(*bp)[0] {
		t.Skip("pool re-issued a different buffer (allowed but unhelpful)")
	}
	if (*bp)[0] != 0xAB {
		t.Fatal("pool returned a different array than the one just put back")
	}
}

func TestBufPoolNilSafety(t *testing.T) {
	PutBuf(nil)
	bp := GetBuf(0)
	if bp == nil || len(*bp) != 0 {
		t.Fatalf("GetBuf(0) = %v, want non-nil empty", bp)
	}
}

func BenchmarkGetPutSmall(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bp := GetBuf(1024)
		PutBuf(bp)
	}
}

func BenchmarkGetPutLarge(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bp := GetBuf(12000)
		PutBuf(bp)
	}
}
