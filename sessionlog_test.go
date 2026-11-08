package main

// sessionlog_test.go —— 会话日志内核测试。
// 覆盖：脱敏（控制字符 / JWT / 键值令牌 / 限长）、环形缓冲（限行 / 限字节）、
// 文件名生成、落盘-回读往返、列表排序、轮转删除、脏文件容错。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSanitizeSessionLogLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"控制字符剥离", "line1\r\n\x1b[31mred\x00tail", "line1 red tail"},
		{"普通文本保留", "Loading 42 chunks", "Loading 42 chunks"},
		{"JWT整段替换", "auth eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.x", "[REDACTED-JWT]"},
		{"键值长令牌替换", "access_token=abcdefghijklmnopqrstuvwxyz012345", "access_token=[REDACTED]"},
		{"短键值不误伤", "count=5", "count=5"},
		{"超长截断", strings.Repeat("x", maxSessionLogLineBytes+50), strings.Repeat("x", maxSessionLogLineBytes)},
		{"纯控制字符", "\x00\x01\x02", ""},
	}
	for _, c := range cases {
		got := sanitizeSessionLogLine(c.in, maxSessionLogLineBytes)
		if got != c.want {
			t.Errorf("%s: 期望 %q, 得到 %q", c.name, c.want, got)
		}
	}
}

func TestSanitizeSessionLogLineCustomMax(t *testing.T) {
	got := sanitizeSessionLogLine("abcdefgh", 4)
	if got != "abcd" {
		t.Fatalf("自定义限长失败: %q", got)
	}
}

func TestAppendSessionLogLineRing(t *testing.T) {
	buf := newSessionLogBuffer()
	base := time.Unix(1700000000, 0)
	for i := 0; i < maxSessionLogLines+10; i++ {
		var ok bool
		buf, ok = appendSessionLogLine(buf, base.Add(time.Duration(i)*time.Second), "line-"+string(rune('a'+i%26)))
		if !ok {
			t.Fatalf("第 %d 行不应超限", i)
		}
	}
	if len(buf.lines) != maxSessionLogLines {
		t.Fatalf("环形应保持 %d 行, 实际 %d", maxSessionLogLines, len(buf.lines))
	}
	// 写入 2010 行丢弃最旧 10 行；第 10 行文本 = "line-" + ('a'+10) = 'k'。
	if buf.lines[0].Text != "line-k" {
		t.Fatalf("环形丢弃最旧行失败, 首行 %q", buf.lines[0].Text)
	}
}

func TestAppendSessionLogLineBytesLimit(t *testing.T) {
	buf := newSessionLogBuffer()
	base := time.Unix(1700000000, 0)
	// 写超大行直到总量超限。
	var ok bool
	for i := 0; i < 10000; i++ {
		buf, ok = appendSessionLogLine(buf, base, strings.Repeat("y", maxSessionLogLineBytes))
		if !ok {
			break
		}
	}
	if ok {
		t.Fatalf("总量应最终超限, 但一直成功")
	}
	if buf.bytes > maxSessionLogBytes {
		t.Fatalf("缓冲字节 %d 超过上限 %d", buf.bytes, maxSessionLogBytes)
	}
}

func TestSessionLogFileNameAndPath(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 5, 0, time.UTC)
	name := sessionLogFileNameFor("1.21", now)
	if name != "sessionlog-1.21-20260929T120005.json" {
		t.Fatalf("文件名不符: %s", name)
	}
	p := sessionLogFilePathFor("C:\\qgl", "1.21", now)
	if !strings.HasSuffix(p, name) {
		t.Fatalf("路径拼接不符: %s", p)
	}
}

func TestPersistAndReadSessionLog(t *testing.T) {
	dir := t.TempDir()
	buf := newSessionLogBuffer()
	base := time.Unix(1700000000, 0)
	for i := 0; i < 3; i++ {
		var ok bool
		buf, ok = appendSessionLogLine(buf, base.Add(time.Duration(i)*time.Second), "hello-"+string(rune('0'+i)))
		if !ok {
			t.Fatal("不应超限")
		}
	}
	path := filepath.Join(dir, "sessionlog-1.21-20260929T120005.json")
	if err := persistSessionLog(path, buf); err != nil {
		t.Fatalf("落盘失败: %v", err)
	}
	// Windows 上 os.Chmod 只影响只读位（safeio 注释已说明），因此不在此断言
	// 权限位；落盘原子私有写的权限收敛由 safeio 内核保证（POSIX 语义 0600）。
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	lines := readSessionLog(path)
	if len(lines) != 3 {
		t.Fatalf("回读行数应为 3, 实际 %d", len(lines))
	}
	if lines[0].Text != "hello-0" {
		t.Fatalf("回读内容不符: %q", lines[0].Text)
	}
}

func TestPersistEmptySessionLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessionlog-1.21-20260929T120006.json")
	if err := persistSessionLog(path, newSessionLogBuffer()); err != nil {
		t.Fatalf("空日志落盘应成功: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("空日志不应落盘文件")
	}
}

func TestListSessionLogSummariesSort(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for i := 0; i < 5; i++ {
		name := sessionLogFileNameFor("1.21", now.Add(-time.Duration(i)*time.Minute))
		_ = os.WriteFile(filepath.Join(dir, name), []byte(`[{"ts":"x","text":"y"}]`), 0600)
	}
	sums := listSessionLogSummaries(dir, 3)
	if len(sums) != 3 {
		t.Fatalf("limit=3 应返回 3 份, 实际 %d", len(sums))
	}
	// 倒序：最新的在首位。
	for i := 1; i < len(sums); i++ {
		if sums[i-1].Name < sums[i].Name {
			t.Fatalf("列表未按新→旧排序: %s 在 %s 前", sums[i-1].Name, sums[i].Name)
		}
	}
}

func TestRotateSessionLogs(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for i := 0; i < 6; i++ {
		name := sessionLogFileNameFor("1.21", now.Add(-time.Duration(i)*time.Minute))
		_ = os.WriteFile(filepath.Join(dir, name), []byte(`[{"ts":"x","text":"y"}]`), 0600)
	}
	removed := rotateSessionLogs(dir, 4)
	if removed != 2 {
		t.Fatalf("应删除 2 个最旧文件, 实际 %d", removed)
	}
	remaining := listSessionLogSummaries(dir, 0)
	if len(remaining) != 4 {
		t.Fatalf("应剩 4 份, 实际 %d", len(remaining))
	}
}

func TestSessionLogTailSanitizesAndBounds(t *testing.T) {
	dir := t.TempDir()
	buf := newSessionLogBuffer()
	base := time.Unix(1700000000, 0)
	for i := 0; i < 10; i++ {
		var ok bool
		buf, ok = appendSessionLogLine(buf, base.Add(time.Duration(i)*time.Second), "row-"+string(rune('0'+i)))
		if !ok {
			t.Fatal("不应超限")
		}
	}
	name := sessionLogFileNameFor("1.21", time.Now())
	path := filepath.Join(dir, name)
	if err := persistSessionLog(path, buf); err != nil {
		t.Fatal(err)
	}
	tail := sessionLogTail(dir, name, 3)
	if len(tail) != 3 {
		t.Fatalf("尾部应 3 行, 实际 %d", len(tail))
	}
	if tail[0].Text != "row-7" {
		t.Fatalf("尾部起点不符: %q", tail[0].Text)
	}
	// 脏文件名与目录穿越拒绝。
	if sessionLogTail(dir, "../evil.json", 3) != nil {
		t.Fatal("目录穿越文件名应被拒绝")
	}
}

func TestReadSessionLogDirtyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessionlog-1.21-20260929T120010.json")
	_ = os.WriteFile(path, []byte(`[{"ts":"x","text":`), 0600) // 截断 JSON
	lines := readSessionLog(path)
	if lines != nil {
		t.Fatalf("脏文件应返回空, 实际 %d 行", len(lines))
	}
}
