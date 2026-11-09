package main

import (
	"strconv"
)

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
