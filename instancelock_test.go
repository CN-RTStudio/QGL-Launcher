package main

// instancelock_test.go —— 实例并发启动锁内核测试。
//
// 决策逻辑是纯函数（decideInstanceLock），不依赖真实锁文件即可覆盖：无锁放行、
// 新鲜锁拦截、过期锁接管、脏字段兜底、sanitize 拒绝非法输入、文件名/令牌构造。
// App 绑定（acquire/release）涉及 QGL 目录与真实文件，这里只做内核级断言。

import (
	"strings"
	"testing"
	"time"
)

func TestDecideInstanceLockNoLock(t *testing.T) {
	v := decideInstanceLock(nil, time.Now().UnixMilli(), instanceLockStaleAfter)
	if v.Kind != InstanceLockAllow {
		t.Fatalf("无锁时应放行: %+v", v)
	}
}

func TestDecideInstanceLockFreshBlocks(t *testing.T) {
	now := time.Now().UnixMilli()
	lock := makeInstanceLock("1.20.1", "1.20.1", 12345, "tok", now)
	v := decideInstanceLock(lock, now+1000, instanceLockStaleAfter)
	if v.Kind != InstanceLockBlock {
		t.Fatalf("新鲜锁应拦截: %+v", v)
	}
	if !strings.Contains(v.Reason, "已在运行") {
		t.Fatalf("拦截原因不清晰: %q", v.Reason)
	}
}

func TestDecideInstanceLockStaleReclaims(t *testing.T) {
	now := time.Now().UnixMilli()
	stale := now - int64(instanceLockStaleAfter/time.Millisecond) - 1000
	lock := makeInstanceLock("1.20.1", "1.20.1", 12345, "tok", stale)
	v := decideInstanceLock(lock, now, instanceLockStaleAfter)
	if v.Kind != InstanceLockReclaim {
		t.Fatalf("过期锁应允许接管: %+v", v)
	}
}

func TestDecideInstanceLockDirtyFields(t *testing.T) {
	now := time.Now().UnixMilli()
	base := makeInstanceLock("1.20.1", "1.20.1", 12345, "tok", now)
	cases := []struct {
		label string
		mut   func(*InstanceLock)
	}{
		{"版本不兼容", func(l *InstanceLock) { l.Version = 99 }},
		{"空令牌", func(l *InstanceLock) { l.Token = "" }},
		{"非法PID", func(l *InstanceLock) { l.PID = 0 }},
		{"非法时间", func(l *InstanceLock) { l.StartedAt = 0 }},
	}
	for _, c := range cases {
		l := *base
		c.mut(&l)
		if v := decideInstanceLock(&l, now, instanceLockStaleAfter); v.Kind != InstanceLockReclaim {
			t.Fatalf("%s: 脏锁应按残留处理, got %+v", c.label, v)
		}
	}
}

func TestSanitizeInstanceLock(t *testing.T) {
	ok := makeInstanceLock("1.20.1", "1.20.1", 12345, "tok", time.Now().UnixMilli())
	if !sanitizeInstanceLock(ok) {
		t.Fatalf("干净锁应通过净化")
	}
	bad := []struct {
		label string
		mut   func(*InstanceLock)
	}{
		{"版本错误", func(l *InstanceLock) { l.Version = 2 }},
		{"版本ID穿越", func(l *InstanceLock) { l.VersionID = "../x" }},
		{"版本ID含路径", func(l *InstanceLock) { l.VersionID = "a/b" }},
		{"Dir含反斜杠", func(l *InstanceLock) { l.Dir = "a\\b" }},
		{"Dir超长", func(l *InstanceLock) { l.Dir = strings.Repeat("d", 257) }},
		{"空令牌", func(l *InstanceLock) { l.Token = "" }},
		{"PID非法", func(l *InstanceLock) { l.PID = -1 }},
		{"时间非法", func(l *InstanceLock) { l.StartedAt = -1 }},
	}
	for _, b := range bad {
		l := *ok
		b.mut(&l)
		if sanitizeInstanceLock(&l) {
			t.Fatalf("%s: 非法锁应被拒绝", b.label)
		}
	}
}

func TestInstanceLockFileName(t *testing.T) {
	name := instanceLockFileName("1.20.1")
	if !strings.Contains(name, "1.20.1") || !strings.HasSuffix(name, ".lock") {
		t.Fatalf("锁文件名不符: %q", name)
	}
}

func TestRemoveInstanceLockTokenMismatch(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/instance.lock"
	lock := makeInstanceLock("1.20.1", "1.20.1", 12345, "correct-token", time.Now().UnixMilli())
	if err := saveInstanceLock(path, lock); err != nil {
		t.Fatalf("写锁失败: %v", err)
	}
	if err := removeInstanceLock(path, "wrong-token"); err == nil {
		t.Fatalf("令牌不匹配应拒绝删除")
	}
	if err := removeInstanceLock(path, "correct-token"); err != nil {
		t.Fatalf("令牌匹配应删除成功: %v", err)
	}
}
