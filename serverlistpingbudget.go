package main

// serverlistpingbudget.go —— 服务器列表 ping 预算。
//
// 启动器主界面允许用户塞几百个服务器地址，每个都做一次 Server List Ping。
// 恶意服务器列表（或被劫持的列表源）会让启动器同时对大量内网/回环主机
// 发起连接，变成 SSRF 放大器。这里把"当前还能对哪些主机发 ping"收敛成一个
// 进程内有界预算：同主机 1 秒内只发一次，全局并发 ping 数封顶。

import (
	"sync"
	"time"
)

// ServerPingBudget 按主机名做节流，并限制并发。
type ServerPingBudget struct {
	mu          sync.Mutex
	lastSeen    map[string]time.Time
	inFlight    int
	maxInFlight int
	minInterval time.Duration
	nowFn       func() time.Time
}

// NewServerPingBudget 构造预算。maxInFlight<=0 时默认 8，minInterval<=0 默认 1s。
func NewServerPingBudget(maxInFlight int, minInterval time.Duration) *ServerPingBudget {
	if maxInFlight <= 0 {
		maxInFlight = 8
	}
	if minInterval <= 0 {
		minInterval = time.Second
	}
	return &ServerPingBudget{
		lastSeen:    make(map[string]time.Time),
		maxInFlight: maxInFlight,
		minInterval: minInterval,
		nowFn:       time.Now,
	}
}

// TryAcquire 尝试拿到对 host 的 ping 配额。
// 返回 (ok, release)。ok=false 时 release 是 nil。
// ok=true 时调用方必须在 ping 结束后调用 release()。
func (b *ServerPingBudget) TryAcquire(host string) (bool, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.nowFn()
	if b.inFlight >= b.maxInFlight {
		return false, nil
	}
	if last, ok := b.lastSeen[host]; ok && now.Sub(last) < b.minInterval {
		return false, nil
	}
	b.lastSeen[host] = now
	b.inFlight++
	released := false
	return true, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if !released {
			released = true
			b.inFlight--
		}
	}
}

// InFlight 当前在飞的 ping 数。
func (b *ServerPingBudget) InFlight() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inFlight
}
