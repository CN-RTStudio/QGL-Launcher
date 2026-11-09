package main

import (
	"testing"
	"time"
)

func TestWaitForServerStopAlreadyStopped(t *testing.T) {
	calls := 0
	if !waitForServerStop(func() bool { calls += 1; return false }, time.Second, time.Millisecond) {
		t.Fatalf("已停止时应立即返回 true")
	}
	if calls != 1 {
		t.Fatalf("已停止时只应探测一次, got %d", calls)
	}
}

func TestWaitForServerStopPollsUntilExit(t *testing.T) {
	polls := 0
	ok := waitForServerStop(func() bool {
		polls += 1
		return polls < 5
	}, 2*time.Second, time.Millisecond)
	if !ok || polls != 5 {
		t.Fatalf("应在第 5 次探测到退出, ok=%v polls=%d", ok, polls)
	}
}

func TestWaitForServerStopTimesOut(t *testing.T) {
	start := time.Now()
	ok := waitForServerStop(func() bool { return true }, 50*time.Millisecond, 20*time.Millisecond)
	if ok {
		t.Fatalf("持续运行时应超时返回 false")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("超时判定耗时过长: %s", time.Since(start))
	}
}

func TestWaitForServerStopNilProbe(t *testing.T) {
	if !waitForServerStop(nil, time.Second, time.Millisecond) {
		t.Fatalf("缺少探测函数时应按已停止处理")
	}
}
