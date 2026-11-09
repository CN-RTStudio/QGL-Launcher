package main

// ratelimit.go —— 内存固定窗口限流器。
//
// 用于给登录 / 外置登录刷新等敏感接口加一层保护，防止恶意前端或被攻陷的 webview
// 在短时间内把上游认证端点打爆（暴力尝试密码、刷 token 等）。这是纯内存限流器，
// 不落盘、不发起网络调用，按 key 各自计数，窗口过期后自动回收。

import (
	"sync"
	"time"
)

// simpleRateLimiter 是一个固定窗口计数器限流器。
type simpleRateLimiter struct {
	mu        sync.Mutex
	windows   map[string]*rateWindow
	maxBurst  int
	window    time.Duration
	lastPurge time.Time
}

// rateWindow 记录单个 key 在当前窗口内已放行的次数与窗口重置时刻。
type rateWindow struct {
	count   int
	resetAt time.Time
}

// evictSweepAt 是 map 至少长到这个规模才触发一次全表清扫的阈值。
// key 数量很小时清扫毫无收益，频繁全表遍历反而浪费；达到阈值后顺手回收过期项。
const evictSweepAt = 256

// newRateLimiter 构造一个在 window 时长内每个 key 最多放行 maxBurst 次的限流器。
func newRateLimiter(maxBurst int, window time.Duration) *simpleRateLimiter {
	return &simpleRateLimiter{
		windows:   make(map[string]*rateWindow),
		maxBurst:  maxBurst,
		window:    window,
		lastPurge: time.Now(),
	}
}

// purgeExpired 删除所有已过期窗口。调用方必须持有 mu。
//
// 这一步必须有：Allow 的 key 直接取自用户名（"ygg-"+username 等），攻击者可以不断
// 换名字制造大量唯一 key，旧实现从不删除过期项，map 会随时间无限增长，最终把内存吃光
// （自造 DoS）。
func (l *simpleRateLimiter) purgeExpired(now time.Time) {
	for k, w := range l.windows {
		if now.After(w.resetAt) {
			delete(l.windows, k)
		}
	}
	l.lastPurge = now
}

// Allow 报告 key 这次调用是否被允许。超过 maxBurst 的调用直接拒绝。
func (l *simpleRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	// 距离上次清扫超过一个窗口，或 key 数已偏多，就顺手清掉过期项。
	if len(l.windows) >= evictSweepAt || now.Sub(l.lastPurge) >= l.window {
		l.purgeExpired(now)
	}

	w, ok := l.windows[key]
	if !ok || now.After(w.resetAt) {
		l.windows[key] = &rateWindow{count: 1, resetAt: now.Add(l.window)}
		return true
	}
	if w.count >= l.maxBurst {
		return false
	}
	w.count++
	return true
}

// Remaining 返回某 key 在当前窗口内还能放行多少次（不产生计数副作用）。
// 主要用于给上层返回“稍后再试”类提示；窗口不存在或已过期时返回 maxBurst。
func (l *simpleRateLimiter) Remaining(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, ok := l.windows[key]
	if !ok || now.After(w.resetAt) {
		return l.maxBurst
	}
	left := l.maxBurst - w.count
	if left < 0 {
		return 0
	}
	return left
}

// RetryAfter 返回某 key 需要等待多久才会进入下一个窗口。
// 仍有剩余额度或窗口已过期时返回 0；否则返回到 resetAt 的剩余时长。
func (l *simpleRateLimiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w, ok := l.windows[key]
	if !ok || now.After(w.resetAt) {
		return 0
	}
	if w.count < l.maxBurst {
		return 0
	}
	d := w.resetAt.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// 全局限流器：登录类接口 5 分钟内最多 10 次。
var authRateLimiter = newRateLimiter(10, 5*time.Minute)
