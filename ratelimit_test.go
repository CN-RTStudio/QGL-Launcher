package main

import (
	"strconv"
	"testing"
	"time"
)

func TestRateLimiterBurst(t *testing.T) {
	l := newRateLimiter(3, 50*time.Millisecond)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("第 %d 次应放行", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("第 4 次应被限流")
	}
	// 不同 key 互不影响。
	if !l.Allow("other") {
		t.Fatal("其它 key 应有独立窗口")
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	l := newRateLimiter(1, 30*time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("首次应放行")
	}
	if l.Allow("k") {
		t.Fatal("窗口内应被限流")
	}
	time.Sleep(45 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("窗口过期后应重新放行")
	}
}

// TestRateLimiterPurgesExpiredKeys 验证旧实现的内存无限增长问题已修复：
// 大量唯一 key 的窗口过期后，下一次 Allow 触发清扫，过期项必须被回收。
func TestRateLimiterPurgesExpiredKeys(t *testing.T) {
	l := newRateLimiter(1, 10*time.Millisecond)
	for i := 0; i < evictSweepAt+10; i++ {
		l.Allow("user-" + strconv.Itoa(i))
	}
	if len(l.windows) < evictSweepAt {
		t.Fatalf("清扫前应保留这些新窗口，实际 %d", len(l.windows))
	}
	time.Sleep(20 * time.Millisecond)
	l.Allow("trigger") // 此刻所有旧窗口都已过期，应被全表清扫
	if len(l.windows) != 1 {
		t.Fatalf("过期键应被清扫，仅剩 trigger，实际 %d 个", len(l.windows))
	}
}

func TestRateLimiterManualPurge(t *testing.T) {
	l := newRateLimiter(2, time.Hour)
	l.Allow("a")
	l.Allow("b")
	now := time.Now()
	// 手动把一个窗口改成过期，purgeExpired 应只删过期项、保留有效项。
	l.mu.Lock()
	l.windows["a"].resetAt = now.Add(-time.Second)
	l.purgeExpired(now)
	l.mu.Unlock()
	if _, ok := l.windows["a"]; ok {
		t.Fatal("过期窗口 a 应被删除")
	}
	if _, ok := l.windows["b"]; !ok {
		t.Fatal("有效窗口 b 应保留")
	}
}

func TestRateLimiterRemaining(t *testing.T) {
	l := newRateLimiter(3, time.Hour)
	// 从未见过的 key 剩余额度等于 maxBurst。
	if r := l.Remaining("new"); r != 3 {
		t.Fatalf("新 key 剩余应为 3，实际 %d", r)
	}
	l.Allow("k")
	l.Allow("k")
	if r := l.Remaining("k"); r != 1 {
		t.Fatalf("放行 2 次后剩余应为 1，实际 %d", r)
	}
	l.Allow("k")
	if r := l.Remaining("k"); r != 0 {
		t.Fatalf("打满后剩余应为 0，实际 %d", r)
	}
	// Remaining 不产生计数副作用：连续调用结果一致。
	if r := l.Remaining("k"); r != 0 {
		t.Fatalf("Remaining 不应消耗额度，实际 %d", r)
	}
}

func TestRateLimiterRetryAfter(t *testing.T) {
	l := newRateLimiter(2, 40*time.Millisecond)
	// 仍有额度时无需等待。
	l.Allow("k")
	if d := l.RetryAfter("k"); d != 0 {
		t.Fatalf("有剩余额度时 RetryAfter 应为 0，实际 %v", d)
	}
	// 未知 key 也无需等待。
	if d := l.RetryAfter("nope"); d != 0 {
		t.Fatalf("未知 key RetryAfter 应为 0，实际 %v", d)
	}
	// 打满后应给出正数等待时长，且不超过窗口长度。
	l.Allow("k")
	d := l.RetryAfter("k")
	if d <= 0 {
		t.Fatal("被限流时 RetryAfter 应为正时长")
	}
	if d > 40*time.Millisecond {
		t.Fatalf("等待时长不应超过窗口，实际 %v", d)
	}
	// 窗口过期后归零。
	time.Sleep(50 * time.Millisecond)
	if d := l.RetryAfter("k"); d != 0 {
		t.Fatalf("窗口过期后应归零，实际 %v", d)
	}
}
