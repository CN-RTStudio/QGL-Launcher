package main

import (
	"net/http"
	"testing"
	"time"
)

func TestClampPollInterval(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want time.Duration
	}{
		{"zero falls back to min", 0, deviceCodeMinInterval},
		{"negative falls back to min", -3, deviceCodeMinInterval},
		{"below min", 1, deviceCodeMinInterval},
		{"normal value kept", 17, 17 * time.Second},
		{"boundary min", 5, 5 * time.Second},
		{"huge value capped", 999999, deviceCodeMaxInterval},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := clampPollInterval(c.in); got != c.want {
				t.Fatalf("clampPollInterval(%d) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestClampDeviceTTL(t *testing.T) {
	if got := clampDeviceTTL(0); got != deviceCodeDefaultTTL {
		t.Fatalf("zero ttl = %v, want default %v", got, deviceCodeDefaultTTL)
	}
	if got := clampDeviceTTL(-60); got != deviceCodeDefaultTTL {
		t.Fatalf("negative ttl = %v, want default %v", got, deviceCodeDefaultTTL)
	}
	if got := clampDeviceTTL(900); got != 15*time.Minute {
		t.Fatalf("normal ttl = %v, want 15m", got)
	}
	if got := clampDeviceTTL(86400); got != deviceCodeMaxTTL {
		t.Fatalf("huge ttl = %v, want cap %v", got, deviceCodeMaxTTL)
	}
}

func TestTokenExpiryUnix(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := now.Add(24 * time.Hour).Unix()

	if got := tokenExpiryUnix(now, 86400); got != base {
		t.Fatalf("normal expiry = %d, want %d", got, base)
	}
	// 非正值回退 24h，而不是"现在"（那会立刻被判成过期）。
	if got := tokenExpiryUnix(now, 0); got != base {
		t.Fatalf("zero expiry = %d, want fallback %d", got, base)
	}
	if got := tokenExpiryUnix(now, -5); got != base {
		t.Fatalf("negative expiry = %d, want fallback %d", got, base)
	}
	// 超大值钳到一年。
	want := now.Add(time.Duration(tokenMaxLifetimeSeconds) * time.Second).Unix()
	if got := tokenExpiryUnix(now, 999_999_999); got != want {
		t.Fatalf("huge expiry = %d, want cap %d", got, want)
	}
}

func TestBackoffDeviceInterval(t *testing.T) {
	if got := backoffDeviceInterval(5 * time.Second); got != 10*time.Second {
		t.Fatalf("5s backoff = %v, want 10s", got)
	}
	if got := backoffDeviceInterval(deviceCodeMaxInterval); got != deviceCodeMaxInterval {
		t.Fatalf("backoff above cap = %v, want cap %v", got, deviceCodeMaxInterval)
	}
	// 极小输入也不会跌破最小间隔。
	if got := backoffDeviceInterval(time.Nanosecond); got != deviceCodeMinInterval {
		t.Fatalf("tiny backoff = %v, want min %v", got, deviceCodeMinInterval)
	}
	// 连续退避序列必须单调不减且封顶。
	cur := deviceCodeMinInterval
	for i := 0; i < 20; i++ {
		next := backoffDeviceInterval(cur)
		if next < cur {
			t.Fatalf("backoff decreased: %v -> %v", cur, next)
		}
		if next > deviceCodeMaxInterval {
			t.Fatalf("backoff exceeded cap: %v", next)
		}
		cur = next
	}
}

func TestParseRetryAfterDelay(t *testing.T) {
	if got := parseRetryAfterDelay(""); got != 0 {
		t.Fatalf("empty = %v, want 0", got)
	}
	if got := parseRetryAfterDelay("0"); got != 0 {
		t.Fatalf("zero = %v, want 0", got)
	}
	if got := parseRetryAfterDelay("-15"); got != 0 {
		t.Fatalf("negative = %v, want 0", got)
	}
	if got := parseRetryAfterDelay("not-a-number"); got != 0 {
		t.Fatalf("garbage = %v, want 0", got)
	}
	if got := parseRetryAfterDelay("30"); got != 30*time.Second {
		t.Fatalf("30 = %v, want 30s", got)
	}
	// 超大秒数被钳到轮询上限，不能让 goroutine 睡几小时。
	if got := parseRetryAfterDelay("999999"); got != deviceCodeMaxInterval {
		t.Fatalf("huge = %v, want cap %v", got, deviceCodeMaxInterval)
	}
	// HTTP-date 形式：给一个 45 秒后的时刻，应落在约 45s（容忍调度误差，校验区间）。
	future := time.Now().Add(45 * time.Second).UTC().Format(http.TimeFormat)
	got := parseRetryAfterDelay(future)
	if got < 40*time.Second || got > 50*time.Second {
		t.Fatalf("http-date = %v, want ~45s", got)
	}
	// 过去的 HTTP-date 一律忽略。
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := parseRetryAfterDelay(past); got != 0 {
		t.Fatalf("past http-date = %v, want 0", got)
	}
}

func TestIsAllowedVerificationURL(t *testing.T) {
	allow := []string{
		"https://www.microsoft.com/link",
		"https://microsoft.com/link",
		"https://login.live.com/oauth20_remoteconnect.srf",
		"https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode",
	}
	for _, u := range allow {
		if !isAllowedVerificationURL(u) {
			t.Errorf("expected allowed: %s", u)
		}
	}

	deny := []string{
		"http://www.microsoft.com/link",                       // 明文 http
		"https://micr0soft.com/link",                          // 拼写近似的钓鱼域
		"https://microsoft.com.evil.com/link",                 // 后缀伪造
		"https://evil.com/link",                               // 完全无关主机
		"https://www.microsoft.com@evil.com/link",             // userinfo 视觉混淆
		"javascript:alert(1)",                                 // 非 http(s)
		"file:///C:/Windows/System32/",                        // 本地文件
		"",                                                    // 空
		"https://127.0.0.1/link",                              // 回环 IP（非微软主机）
		"https://10.0.0.5/link",                               // 内网 IP
	}
	for _, u := range deny {
		if isAllowedVerificationURL(u) {
			t.Errorf("expected denied: %q", u)
		}
	}
}
