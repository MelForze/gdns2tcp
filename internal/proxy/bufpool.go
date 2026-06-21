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
//
// The Get/Put API works with `*[]byte`, not `[]byte`. The pointer version
// avoids the 24-byte slice-header escape that `Put(&local)` would incur on
// every release — at axchgWorkers=16 × dozens of tunnels × hundreds of
// release calls per second, that escape adds up.
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

// GetBuf returns a pooled buffer wrapped in `*[]byte`. The slice's len is
// the size you requested; cap is the size class it was drawn from. Pass the
// returned pointer to PutBuf when done.
//
// Sizes that fall outside the class set are heap-allocated and PutBuf on
// them silently drops the buffer — cheap fallback so callers don't have to
// special-case unusual sizes.
func GetBuf(size int) *[]byte {
	if size <= 0 {
		empty := []byte{}
		return &empty
	}
	switch {
	case size <= bufSizeSmall:
		bp := poolSmall.Get().(*[]byte)
		*bp = (*bp)[:size]
		return bp
	case size <= bufSizeMedium:
		bp := poolMedium.Get().(*[]byte)
		*bp = (*bp)[:size]
		return bp
	case size <= bufSizeLarge:
		bp := poolLarge.Get().(*[]byte)
		*bp = (*bp)[:size]
		return bp
	case size <= bufSizeBulk:
		bp := poolBulk.Get().(*[]byte)
		*bp = (*bp)[:size]
		return bp
	default:
		one := make([]byte, size)
		return &one
	}
}

// PutBuf returns a buffer obtained from GetBuf. The routing key is cap();
// the pointer itself is what goes back into sync.Pool, so no slice-header
// escape per Put. Safe to call with nil.
func PutBuf(bp *[]byte) {
	if bp == nil {
		return
	}
	c := cap(*bp)
	switch c {
	case bufSizeSmall:
		poolSmall.Put(bp)
	case bufSizeMedium:
		poolMedium.Put(bp)
	case bufSizeLarge:
		poolLarge.Put(bp)
	case bufSizeBulk:
		poolBulk.Put(bp)
	}
}
