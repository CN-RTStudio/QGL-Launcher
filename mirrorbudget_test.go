package main

import (
	"testing"
	"time"
)

func TestPlanMirrorAttemptsDedupesAndCaps(t *testing.T) {
	urls := []string{"https://a.test/x.jar", " https://a.test/x.jar ", "", "https://b.test/x.jar"}
	plan := planMirrorAttempts(urls, time.Now())
	if len(plan.URLs) != 2 {
		t.Fatalf("应去掉空白与重复镜像, got %v", plan.URLs)
	}
	if plan.URLs[0] != "https://a.test/x.jar" || plan.URLs[1] != "https://b.test/x.jar" {
		t.Fatalf("顺序应保持原样, got %v", plan.URLs)
	}
	many := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		many = append(many, "https://m"+string(rune('a'+i))+".test/x.jar")
	}
	if got := planMirrorAttempts(many, time.Now()); len(got.URLs) != mirrorMaxAttempts {
		t.Fatalf("镜像数量应封顶 %d, got %d", mirrorMaxAttempts, len(got.URLs))
	}
}

func TestMirrorPlanBudgetExpiry(t *testing.T) {
	start := time.Now()
	plan := planMirrorAttempts([]string{"https://a.test/x.jar"}, start)
	if plan.expired(start) {
		t.Fatalf("刚开始不应判定超预算")
	}
	if !plan.expired(start.Add(mirrorFallbackBudget + time.Second)) {
		t.Fatalf("超过预算应判定过期")
	}
	if (mirrorPlan{Start: start}).expired(start.Add(time.Hour)) {
		t.Fatalf("预算为 0 表示不限时")
	}
}

func TestMirrorFallbackDelayGrowsAndCaps(t *testing.T) {
	if got := mirrorFallbackDelay(0); got != 500*time.Millisecond {
		t.Fatalf("第一次退避应为 500ms, got %s", got)
	}
	if got := mirrorFallbackDelay(3); got != 2*time.Second {
		t.Fatalf("第四次退避应为 2s, got %s", got)
	}
	if got := mirrorFallbackDelay(99); got != mirrorFallbackCap {
		t.Fatalf("退避应封顶 %s, got %s", mirrorFallbackCap, got)
	}
	if got := mirrorFallbackDelay(-5); got != 500*time.Millisecond {
		t.Fatalf("负数 attempt 应按第一次处理, got %s", got)
	}
}
