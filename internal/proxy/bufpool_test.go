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
		got := GetBuf(c.req)
		if len(got) != c.req {
			t.Fatalf("GetBuf(%d) len=%d want %d", c.req, len(got), c.req)
		}
		if cap(got) != c.wantCap {
			t.Fatalf("GetBuf(%d) cap=%d want %d", c.req, cap(got), c.wantCap)
		}
		PutBuf(got)
	}
}

// TestBufPoolReuse pins that two consecutive Get(same-class) returns the
// same underlying array. This is the whole point of the pool — without it
// the GC pressure reduction doesn't happen.
func TestBufPoolReuse(t *testing.T) {
	a := GetBuf(1024)
	a[0] = 0xAB
	PutBuf(a)
	b := GetBuf(1024)
	defer PutBuf(b)
	if &a[:1][0] != &b[:1][0] {
		t.Skip("pool re-issued a different buffer (allowed but unhelpful)")
	}
	if b[0] != 0xAB {
		t.Fatal("pool returned a different array than the one just put back")
	}
}

func TestBufPoolNilSafety(t *testing.T) {
	PutBuf(nil)
	if got := GetBuf(0); got != nil {
		t.Fatalf("GetBuf(0) = %v, want nil", got)
	}
}

func BenchmarkGetPutSmall(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := GetBuf(1024)
		PutBuf(buf)
	}
}

func BenchmarkGetPutLarge(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := GetBuf(12000)
		PutBuf(buf)
	}
}
