package main

// diskquotaguard.go —— 下载/解压前的磁盘空间预留与配额闸门（区别于 diskspace 的静态检查）。
//
// 背景：
//   diskspaceguard/diskwriteguard 关注"有没有空间、能不能写"。这里管并发场景下的"预留"：多个下载/
//   解压任务并行时，如果每个都只在开始前独立查一次空闲空间，会出现超卖——三个任务都看到 2GB 空闲
//   就各写 2GB，合计需要 6GB，最终中途把磁盘写满，留下半截损坏文件并挤爆系统盘。其它风险：
//     - 未把"解压后膨胀大小"计入预留（压缩包 300MB 解压 3GB）；
//     - 未把同卷其它实例（游戏运行产生存档、日志、崩溃转储）的动态增长计入；
//     - 取消任务后不释放预留；预留双重记账；
//     - 关键系统盘保留水位被击穿（应保留最小安全余量，不能用到 0 字节）。
//   本模块是纯数值记账器：调用方在真正分配前 Reserve、结束/失败后 Release，跨任务共享同一账本。
//   不直接查询文件系统（真实 freeBytes 由调用方喂入），不使用正则。

import "sync"

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
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
