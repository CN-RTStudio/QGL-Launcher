package main

import (
	"sync"
)

const (
	DQReasonExceedsAvailable    = "quota-request-exceeds-available-space"
	DQReasonBelowSafetyReserve  = "quota-would-breach-safety-reserve"
	DQReasonNegativeReservation = "quota-negative-reservation"
	DQReasonReleaseWithoutHold  = "quota-release-without-matching-reservation"
	DQReasonUnknownInstance     = "quota-unknown-reservation-id"
)

// DQFinding 记录一处配额问题。
type DQFinding struct {
	Reason string
	Detail string
}

// DQLedger 是单卷的预留账本，并发安全。
type DQLedger struct {
	mu            sync.Mutex
	totalBytes    int64 // 卷容量（0 表示未知）
	safetyReserve int64 // 必须保留不被占用的安全水位
	freeNow       int64 // 调用方最近一次上报的真实空闲字节
	reserved      int64 // 已被本账本预留的字节
	holds         map[string]int64
}

// NewDQLedger 创建账本。totalBytes=0 时仅按 freeNow 与 safetyReserve 判定。
func NewDQLedger(totalBytes, safetyReserve int64) *DQLedger {
	return &DQLedger{
		totalBytes:    totalBytes,
		safetyReserve: safetyReserve,
		holds:         map[string]int64{},
	}
}

// UpdateFree 由调用方在每次预留前刷新真实空闲字节。
func (l *DQLedger) UpdateFree(freeBytes int64) {
	l.mu.Lock()
	l.freeNow = freeBytes
	l.mu.Unlock()
}

// Reserve 为某任务预留 bytes（id 唯一）。expandBytes 为解压/安装后的额外膨胀量，一并计入。
func (l *DQLedger) Reserve(id string, compressedBytes, expandBytes int64) (granted bool, findings []DQFinding) {
	l.mu.Lock()
	defer l.mu.Unlock()

	need := compressedBytes + expandBytes
	if need < 0 || compressedBytes < 0 || expandBytes < 0 {
		return false, []DQFinding{{Reason: DQReasonNegativeReservation}}
	}
	if _, exists := l.holds[id]; exists {
		// 重复预留同 id：先视为错误，避免双账
		return false, []DQFinding{{Reason: DQReasonNegativeReservation, Detail: "duplicate-id"}}
	}

	available := l.freeNow - l.reserved
	if need > available {
		return false, []DQFinding{{Reason: DQReasonExceedsAvailable,
			Detail: itoaDQ(need) + "/" + itoaDQ(available)}}
	}
	// 预留后不得击穿安全水位
	if available-need < l.safetyReserve {
		return false, []DQFinding{{Reason: DQReasonBelowSafetyReserve,
			Detail: itoaDQ(available - need)}}
	}

	l.holds[id] = need
	l.reserved += need
	return true, nil
}
