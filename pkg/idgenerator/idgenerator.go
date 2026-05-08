package idgenerator

import (
	"sync"
	"time"
)

const (
	ReservedBits = 2 // 2 bits for future use
	sequenceBits = 10
	maxSequence  = -1 ^ (-1 << sequenceBits) // 1023
)

// Generator creates snowflake-like, unique, roughly-ordered int64 ids based on the current time in milliseconds.
type Generator struct {
	mu       sync.Mutex
	lastMs   int64
	seq      int64
	reserved int64
}

func New(reserved int64) *Generator {
	return &Generator{reserved: reserved}
}

// NewID returns an id composed of (nowMs << 10) | sequence.
// It supports up to 1024 ids per millisecond per Generator instance.
func (g *Generator) NewID(nowMs int64) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()

	if nowMs == g.lastMs {
		g.seq = (g.seq + 1) & maxSequence
		if g.seq == 0 {
			// Sequence overflow: wait for next millisecond
			for nowMs <= g.lastMs {
				nowMs = time.Now().UnixMilli()
			}
		}
	} else {
		g.lastMs = nowMs
		g.seq = 0
	}
	return (nowMs << (ReservedBits + sequenceBits)) | (g.reserved << sequenceBits) | g.seq
}
