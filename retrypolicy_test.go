package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryDelayGrowsAndCaps(t *testing.T) {
	base := 100 * time.Millisecond
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
	}
	for _, c := range cases {
		if got := retryDelay(c.attempt, base); got != c.want {
			t.Fatalf("attempt %d 期望 %s, got %s", c.attempt, c.want, got)
		}
	}
	if got := retryDelay(12, base); got != retryBackoffMax {
		t.Fatalf("长期退避应封顶 %s, got %s", retryBackoffMax, got)
	}
	if got := retryDelay(64, base); got != retryBackoffMax {
		t.Fatalf("超大 attempt 应封顶而不是溢出成负值, got %s", got)
	}
	if got := retryDelay(0, base); got != base {
		t.Fatalf("attempt<1 应按第一次处理, got %s", got)
	}
	if got := retryDelay(3, 0); got <= 0 {
		t.Fatalf("base 非正时应回落到正值, got %s", got)
	}
}

func TestRunWithRetryStopsOnFatal(t *testing.T) {
	calls := 0
	used, err := runWithRetry(context.Background(), 5, time.Millisecond, func() (bool, error) {
		calls += 1
		return true, errors.New("bad status")
	})
	if calls != 1 {
		t.Fatalf("fatal 应只尝试一次, got %d", calls)
	}
	if used != 1 || err == nil {
		t.Fatalf("应返回第一次尝试与错误, used=%d err=%v", used, err)
	}
}

func TestRunWithRetrySucceedsAfterTransient(t *testing.T) {
	calls := 0
	used, err := runWithRetry(context.Background(), 4, time.Millisecond, func() (bool, error) {
		calls += 1
		if calls < 3 {
			return false, errors.New("timeout")
		}
		return false, nil
	})
	if err != nil || used != 3 || calls != 3 {
		t.Fatalf("应第 3 次成功, used=%d calls=%d err=%v", used, calls, err)
	}
}

func TestRunWithRetryExhausts(t *testing.T) {
	calls := 0
	used, err := runWithRetry(context.Background(), 3, time.Millisecond, func() (bool, error) {
		calls += 1
		return false, errors.New("still failing")
	})
	if calls != 3 || used != 3 || err == nil {
		t.Fatalf("应尝试 3 次后返回错误, used=%d calls=%d err=%v", used, calls, err)
	}
}

func TestRunWithRetryHonoursContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	used, err := runWithRetry(ctx, 3, time.Millisecond, func() (bool, error) {
		calls += 1
		cancel()
		return false, errors.New("transient")
	})
	if calls != 1 || used != 1 {
		t.Fatalf("取消后不应再重试, used=%d calls=%d", used, calls)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("应返回 context.Canceled, got %v", err)
	}
}
