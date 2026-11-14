package main

import (
	"strconv"
)

func (m *H2Monitor) block(reason, _ string) {
	m.blocked = true
	m.blockedReason = reason
}

// Blocked 报告监控是否已判定需要熔断。
func (m *H2Monitor) Blocked() bool { return m.blocked }

// BlockedReason 返回熔断原因。
func (m *H2Monitor) BlockedReason() string { return m.blockedReason }

// ActiveCount 返回当前活跃流数。
func (m *H2Monitor) ActiveCount() int { return len(m.active) }

func itoaH2(i int) string {
	return strconv.Itoa(i)
}
