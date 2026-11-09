package main

import (
	"strings"
	"testing"
	"time"
)

func TestSanitizeConsoleCommandValid(t *testing.T) {
	cases := []string{
		"say hello",
		"/give @p diamond 64",
		"stop",
		"  say spaced  ",
		"中文聊天消息",
		"/summon minecraft:villager ~ ~ ~ {NoAI:1b}",
	}
	for _, in := range cases {
		got, reason := SanitizeConsoleCommand(in)
		if reason != consoleRejectNone {
			t.Fatalf("合法命令被误拒: %q reason=%s", in, reason)
		}
		if got != strings.TrimSpace(in) {
			t.Fatalf("未正确去除首尾空白: in=%q got=%q", in, got)
		}
	}
}

func TestSanitizeConsoleCommandReject(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"空串", "", consoleRejectEmpty},
		{"纯空白", "   \t  ", consoleRejectEmpty},
		{"LF注入", "say a\nsay b", consoleRejectNewline},
		{"CR注入", "say a\rsay b", consoleRejectNewline},
		{"CRLF注入", "say a\r\nsay b", consoleRejectNewline},
		{"NUL截断", "say\x00oops", consoleRejectControl},
		{"BEL响铃", "say\x07", consoleRejectControl},
		{"ESC转义", "\x1b[31mred", consoleRejectControl},
		{"退格", "say a\x08b", consoleRejectControl},
		{"DEL", "say\x7f", consoleRejectControl},
		{"Unicode行分隔", "say a\u2028b", consoleRejectControl},
		{"Unicode段分隔", "say a\u2029b", consoleRejectControl},
		{"BOM", "\ufeffsay", consoleRejectControl},
		{"超长", strings.Repeat("a", maxConsoleCommandBytes+1), consoleRejectLength},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := SanitizeConsoleCommand(c.in)
			if reason != c.want {
				t.Fatalf("in=%q got=%q want reason=%s actual=%s", c.in, got, c.want, reason)
			}
			if got != "" {
				t.Fatalf("被拒命令不应返回可用内容: got=%q", got)
			}
		})
	}
}

func TestSanitizeConsoleCommandBoundaryLength(t *testing.T) {
	// 恰好等于上限必须放行。
	atLimit := strings.Repeat("a", maxConsoleCommandBytes)
	if _, reason := SanitizeConsoleCommand(atLimit); reason != consoleRejectNone {
		t.Fatalf("长度恰为上限被误拒: %s", reason)
	}
}

func TestSanitizeConsoleCommandInvalidUTF8(t *testing.T) {
	bad := "say " + string([]byte{0xff, 0xfe, 0xfd})
	if _, reason := SanitizeConsoleCommand(bad); reason != consoleRejectEncoding {
		t.Fatalf("非法UTF-8未被拒绝: %s", reason)
	}
}

func TestConsoleCommandGateAllowsUnderThreshold(t *testing.T) {
	var g consoleCommandGate
	now := time.Unix(1_000_000, 0)
	for i := 0; i < consoleBurstMax; i++ {
		if !g.allow(now) {
			t.Fatalf("第 %d 条（阈值内）被误拒", i+1)
		}
		now = now.Add(10 * time.Millisecond)
	}
}

func TestConsoleCommandGateRejectsBurstOverflow(t *testing.T) {
	var g consoleCommandGate
	now := time.Unix(2_000_000, 0)
	for i := 0; i < consoleBurstMax; i++ {
		g.allow(now)
	}
	if g.allow(now) {
		t.Fatal("超过短窗阈值的第 41 条应当被拒绝")
	}
	// 触发后进入冷却，紧随其后的请求一律拒绝。
	if g.allow(now.Add(time.Second)) {
		t.Fatal("冷却期内应当拒绝")
	}
	// 冷却结束后应恢复放行。
	if !g.allow(now.Add(consoleCooldown + time.Second)) {
		t.Fatal("冷却结束后应当恢复放行")
	}
}

func TestConsoleCommandGateRejectsLongWindowOverflow(t *testing.T) {
	var g consoleCommandGate
	now := time.Unix(3_000_000, 0)
	step := consoleLongWindow / time.Duration(consoleLongMax+10)
	for i := 0; i < consoleLongMax; i++ {
		if !g.allow(now) {
			t.Fatalf("长窗内第 %d 条不应被拒", i+1)
		}
		now = now.Add(step)
	}
	if g.allow(now) {
		t.Fatal("超过长窗阈值应当被拒绝")
	}
}

func TestConsoleCommandGateReset(t *testing.T) {
	var g consoleCommandGate
	now := time.Unix(4_000_000, 0)
	for i := 0; i < consoleBurstMax; i++ {
		g.allow(now)
	}
	if g.allow(now) {
		t.Fatal("超阈应拒绝")
	}
	g.reset()
	if !g.allow(now) {
		t.Fatal("reset 后应立即放行")
	}
}
