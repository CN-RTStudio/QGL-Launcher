package main

import (
	"time"
)

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
