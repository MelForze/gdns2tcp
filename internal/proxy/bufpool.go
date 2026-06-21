package proxy

import "sync"

// Buffer-pool size classes. Picked to match the actual chunk sizes the
// proxy hot-path produces:
//
//   - Small (2 KB)  — UDP-axchg plaintext (~92 B) and the per-cid 4-KB
//     operator-read scratch buffer in reversePumpOperator.
//   - Medium (8 KB) — TCP-axchg plaintext in the 5–20 ms RTT band of the
//     adaptive sizer.
//   - Large (16 KB) — TCP-axchg plaintext at LAN RTT (< 5 ms).
//   - Bulk (64 KB)  — DNS-over-TCP frame buffers in the persistent pool.
//
// Anything that doesn't fit any class skips the pool entirely; allocations
// at that size are rare enough that GC absorbs them without spike.
const (
	bufSizeSmall  = 2 * 1024
	bufSizeMedium = 8 * 1024
	bufSizeLarge  = 16 * 1024
	bufSizeBulk   = 64 * 1024
)

var (
	poolSmall  = newBytePool(bufSizeSmall)
	poolMedium = newBytePool(bufSizeMedium)
	poolLarge  = newBytePool(bufSizeLarge)
	poolBulk   = newBytePool(bufSizeBulk)
)

func newBytePool(size int) *sync.Pool {
	return &sync.Pool{
		New: func() any {
			b := make([]byte, size)
			return &b
		},
	}
}

// GetBuf returns a byte slice with len = requested and cap = the size
// class it was drawn from. Caller must pass the returned slice (or a
// reslice of it) to PutBuf when done; PutBuf reads cap() to route back to
// the right pool. Sizes that fall outside the class set are heap-allocated
// and PutBuf silently drops them.
func GetBuf(size int) []byte {
	if size <= 0 {
		return nil
	}
	switch {
	case size <= bufSizeSmall:
		bp := poolSmall.Get().(*[]byte)
		return (*bp)[:size]
	case size <= bufSizeMedium:
		bp := poolMedium.Get().(*[]byte)
		return (*bp)[:size]
	case size <= bufSizeLarge:
		bp := poolLarge.Get().(*[]byte)
		return (*bp)[:size]
	case size <= bufSizeBulk:
		bp := poolBulk.Get().(*[]byte)
		return (*bp)[:size]
	default:
		return make([]byte, size)
	}
}

// PutBuf returns a buffer obtained from GetBuf. The routing key is cap();
// passing a slice that was reshaped to a smaller cap (via three-arg slicing
// or appending to an arbitrary base) will silently miss the pool. Safe to
// call with nil.
func PutBuf(buf []byte) {
	c := cap(buf)
	if c == 0 {
		return
	}
	full := buf[:c]
	switch c {
	case bufSizeSmall:
		poolSmall.Put(&full)
	case bufSizeMedium:
		poolMedium.Put(&full)
	case bufSizeLarge:
		poolLarge.Put(&full)
	case bufSizeBulk:
		poolBulk.Put(&full)
	}
}
