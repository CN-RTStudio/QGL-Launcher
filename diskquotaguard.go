package main

import (
	"strconv"
	"sync"
)

const (
	DQReasonExceedsAvailable    = "quota-request-exceeds-available-space"
	DQReasonBelowSafetyReserve  = "quota-would-breach-safety-reserve"
	DQReasonNegativeReservation = "quota-negative-reservation"
	DQReasonReleaseWithoutHold  = "quota-release-without-matching-reservation"
	DQReasonUnknownInstance     = "quota-unknown-reservation-id"
)

type DQFinding struct {
	Reason string
	Detail string
}
type DQLedger struct {
	mu            sync.Mutex
	totalBytes    int64 // 卷容量（0 表示未知）
	safetyReserve int64 // 必须保留不被占用的安全水位
	freeNow       int64 // 调用方最近一次上报的真实空闲字节
	reserved      int64 // 已被本账本预留的字节
	holds         map[string]int64
}

func NewDQLedger(totalBytes, safetyReserve int64) *DQLedger {
	return &DQLedger{
		totalBytes:    totalBytes,
		safetyReserve: safetyReserve,
		holds:         map[string]int64{},
	}
}

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

// Release 释放某任务的预留（完成/失败/取消都必须调用）。
func (l *DQLedger) Release(id string) (ok bool, findings []DQFinding) {
	l.mu.Lock()
	defer l.mu.Unlock()
	held, exists := l.holds[id]
	if !exists {
		return false, []DQFinding{{Reason: DQReasonReleaseWithoutHold, Detail: id}}
	}
	l.reserved -= held
	if l.reserved < 0 {
		l.reserved = 0
	}
	delete(l.holds, id)
	return true, nil
}

// Reserved 返回当前总预留。
func (l *DQLedger) Reserved() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reserved
}

// HoldCount 返回活跃预留数量。
func (l *DQLedger) HoldCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.holds)
}

// Available 返回在安全水位之上的可用字节。
func (l *DQLedger) Available() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	avail := l.freeNow - l.reserved - l.safetyReserve
	if avail < 0 {
		return 0
	}
	return avail
}

func itoaDQ(i int64) string {
	return strconv.FormatInt(i, 10)
}
