package main

// yggsession_test.go —— 会话令牌生命周期守卫测试。
//
// 覆盖：
//  1. 生命周期决策：ok / expiring-soon / refresh-needed 边界；
//  2. 过期很久的记录被判 invalid（不尝试刷新）；
//  3. 结构校验：空账号、超长字段、控制字符、零过期时间；
//  4. 刷新节流：窗口内第 4 次刷新被拒，窗口过期重置；
//  5. 令牌指纹不泄露本体；
//  6. 账号名净化。

import (
	"strings"
	"testing"
	"time"
)

func TestDecideLifecycle_Boundaries(t *testing.T) {
	now := time.Now()
	if got := DecideLifecycle(now.Add(10*time.Minute), now); got != YggLifecycleExpiringSoon {
		t.Fatalf("10 分钟后到期应 expiring-soon，得到 %s", got)
	}
	if got := DecideLifecycle(now.Add(3*time.Minute), now); got != YggLifecycleRefreshNeeded {
		t.Fatalf("3 分钟后到期应 refresh-needed，得到 %s", got)
	}
	if got := DecideLifecycle(now.Add(-1*time.Second), now); got != YggLifecycleRefreshNeeded {
		t.Fatalf("已过期应 refresh-needed，得到 %s", got)
	}
	if got := DecideLifecycle(now.Add(2*time.Hour), now); got != YggLifecycleOK {
		t.Fatalf("2 小时后到期应 ok，得到 %s", got)
	}
	if got := DecideLifecycle(now.Add(20*time.Minute), now); got != YggLifecycleOK {
		t.Fatalf("20 分钟后到期应 ok（超出 15min 窗口），得到 %s", got)
	}
}

func TestDecideLifecycle_ExpiringSoonWindow(t *testing.T) {
	now := time.Now()
	// 阈值：15 分钟窗口；5 分钟硬性余量。
	if got := DecideLifecycle(now.Add(14*time.Minute), now); got != YggLifecycleExpiringSoon {
		t.Fatalf("14 分钟应 expiring-soon，得到 %s", got)
	}
	if got := DecideLifecycle(now.Add(16*time.Minute), now); got != YggLifecycleOK {
		t.Fatalf("16 分钟应 ok，得到 %s", got)
	}
}

func TestValidateSessionRecord_Valid(t *testing.T) {
	rec := YggSessionRecord{
		AccountName:  "steve@example.com",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		AccessToken:  strings.Repeat("A", 40),
		RefreshToken: strings.Repeat("B", 40),
	}
	ok, reason := ValidateSessionRecord(rec)
	if !ok {
		t.Fatalf("合法记录被判无效: %s", reason)
	}
}

func TestValidateSessionRecord_Rejects(t *testing.T) {
	base := YggSessionRecord{
		AccountName:  "steve",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		AccessToken:  strings.Repeat("A", 40),
		RefreshToken: strings.Repeat("B", 40),
	}
	cases := []struct {
		name string
		mut  func(*YggSessionRecord)
	}{
		{"empty-account", func(r *YggSessionRecord) { r.AccountName = "" }},
		{"long-account", func(r *YggSessionRecord) { r.AccountName = strings.Repeat("x", 300) }},
		{"empty-access", func(r *YggSessionRecord) { r.AccessToken = "" }},
		{"long-access", func(r *YggSessionRecord) { r.AccessToken = strings.Repeat("A", yggMaxFieldLen+1) }},
		{"control-char", func(r *YggSessionRecord) { r.AccessToken = "abc\x01def" }},
		{"zero-expiry", func(r *YggSessionRecord) { r.ExpiresAt = time.Time{} }},
		{"expired-long-ago", func(r *YggSessionRecord) { r.ExpiresAt = time.Now().Add(-48 * time.Hour) }},
	}
	for _, c := range cases {
		rec := base
		c.mut(&rec)
		if ok, _ := ValidateSessionRecord(rec); ok {
			t.Errorf("用例 %q 应被拒绝", c.name)
		}
	}
}

func TestRefreshRegistry_Throttle(t *testing.T) {
	reg := newYggRefreshRegistry()
	now := time.Now()
	for i := 0; i < yggMaxRefreshesPerWindow; i++ {
		ok, count := reg.AllowRefresh("steve", now)
		if !ok {
			t.Fatalf("第 %d 次刷新应放行（上限 %d）", i+1, yggMaxRefreshesPerWindow)
		}
		if count != i+1 {
			t.Fatalf("计数错误: %d != %d", count, i+1)
		}
	}
	ok, count := reg.AllowRefresh("steve", now)
	if ok {
		t.Fatalf("窗口内第 %d 次刷新应被拒", yggMaxRefreshesPerWindow+1)
	}
	if count != yggMaxRefreshesPerWindow {
		t.Fatalf("拒绝时计数应保持 %d，得到 %d", yggMaxRefreshesPerWindow, count)
	}
	// 窗口过期后重置
	late := now.Add(yggRefreshWindow + time.Second)
	ok, count = reg.AllowRefresh("steve", late)
	if !ok || count != 1 {
		t.Fatalf("窗口过期后应重置放行，得到 ok=%v count=%d", ok, count)
	}
}

func TestRefreshRegistry_EmptyAccount(t *testing.T) {
	reg := newYggRefreshRegistry()
	if ok, _ := reg.AllowRefresh("", time.Now()); ok {
		t.Fatal("空账号不应放行刷新")
	}
}

func TestRefreshRegistry_Reset(t *testing.T) {
	reg := newYggRefreshRegistry()
	now := time.Now()
	reg.AllowRefresh("steve", now)
	reg.AllowRefresh("steve", now)
	reg.ResetRefreshes("steve")
	ok, count := reg.AllowRefresh("steve", now)
	if !ok || count != 1 {
		t.Fatalf("重置后应重新从 1 计，得到 ok=%v count=%d", ok, count)
	}
}

func TestTokenFingerprint(t *testing.T) {
	if TokenFingerprint("") != "(none)" {
		t.Fatal("空令牌指纹应为 (none)")
	}
	if TokenFingerprint("short") != "(short)" {
		t.Fatal("短令牌指纹应为 (short)")
	}
	fp := TokenFingerprint("abcdefghijklmnop")
	if fp != "abcd…mnop(16)" {
		t.Fatalf("指纹格式错误: %q", fp)
	}
	if strings.Contains(fp, "efgh") {
		t.Fatal("指纹泄露令牌中间片段")
	}
}

func TestSanitizeSessionName(t *testing.T) {
	if got := sanitizeSessionName("  steve\x01@example.com  "); got != "steve@example.com" {
		t.Fatalf("净化失败: %q", got)
	}
	if got := sanitizeSessionName(strings.Repeat("a", 500)); len(got) != 256 {
		t.Fatalf("截断失败: len=%d", len(got))
	}
}

func TestNextRefreshAllowedAt(t *testing.T) {
	now := time.Now()
	reg := newYggRefreshRegistry()
	reg.AllowRefresh("steve", now)
	next := NextRefreshAllowedAt("steve", reg, now)
	want := now.Add(yggRefreshWindow)
	if !next.Equal(want) {
		t.Fatalf("下次刷新时间错误: %v != %v", next, want)
	}
	// 窗口过期后立即允许
	late := now.Add(yggRefreshWindow + time.Second)
	if got := NextRefreshAllowedAt("steve", reg, late); !got.Equal(late) {
		t.Fatalf("窗口过期后应返回 now: %v", got)
	}
}
