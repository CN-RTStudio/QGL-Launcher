package main

import (
	"time"
)

// allow 判断当前时刻是否放行一条命令；一旦短窗或长窗超阈，立即进入冷却期并拒绝。
// 冷却期结束后所有计数重新开始。
func (g *consoleCommandGate) allow(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if now.Before(g.cooldownUntil) {
		return false
	}
	// 短窗口滑动：距首条已超过窗口则开窗重新计数。
	if g.burstStart.IsZero() || now.Sub(g.burstStart) > consoleBurstWindow {
		g.burstStart = now
		g.burstCount = 0
	}
	// 长窗口滑动。
	if g.longStart.IsZero() || now.Sub(g.longStart) > consoleLongWindow {
		g.longStart = now
		g.longCount = 0
	}

	g.burstCount++
	g.longCount++
	if g.burstCount > consoleBurstMax || g.longCount > consoleLongMax {
		g.cooldownUntil = now.Add(consoleCooldown)
		// 进入冷却即清空窗口，冷却结束后从干净状态重新计数。
		g.burstStart = time.Time{}
		g.burstCount = 0
		g.longStart = time.Time{}
		g.longCount = 0
		return false
	}
	return true
}

// reset 清空限流状态，在新的服务端进程启动时调用，避免上一轮冷却误伤本次会话。
func (g *consoleCommandGate) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.burstStart = time.Time{}
	g.burstCount = 0
	g.longStart = time.Time{}
	g.longCount = 0
	g.cooldownUntil = time.Time{}
}

// serverConsoleGate 是 SendServerCommand 共用的包级限流闸。
var serverConsoleGate consoleCommandGate
