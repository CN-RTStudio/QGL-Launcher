package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestBoundedLogAppendCreatesFile：首次追加会创建文件并原样落盘、自动补换行。
func TestBoundedLogAppendCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "qgl_launch.log")
	lg := getBoundedLogger(path)
	if err := lg.appendBoundedLine("[2026] hello"); err != nil {
		t.Fatalf("appendBoundedLine 返回错误: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取日志文件失败: %v", err)
	}
	if got := string(data); got != "[2026] hello\n" {
		t.Fatalf("落盘内容不符，got=%q", got)
	}
}

// TestBoundedLogRegistrySharedLock：同一路径两次获取必须是同一实例（共享锁）。
func TestBoundedLogRegistrySharedLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.log")
	a := getBoundedLogger(path)
	b := getBoundedLogger(path)
	if a != b {
		t.Fatal("同一路径应返回同一个 boundedLogger 以共享互斥锁")
	}
}

// TestBoundedLogRotation：把上限调小后持续追加，必须触发轮转：
// 产生 .1 归档，且活动文件被重置后从较小起点重新增长，不会无限膨胀。
func TestBoundedLogRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rot.log")
	lg := &boundedLogger{path: path, maxBytes: 128}

	line := strings.Repeat("a", 60) // 60 字节 + 换行 = 61
	for i := 0; i < 10; i++ {
		if err := lg.appendBoundedLine(line); err != nil {
			t.Fatalf("第 %d 次追加失败: %v", i, err)
		}
	}

	backup := path + ".1"
	if _, err := os.Lstat(backup); err != nil {
		t.Fatalf("期望轮转产生归档 .1: %v", err)
	}
	activeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("活动文件应仍存在: %v", err)
	}
	backupInfo, err := os.Stat(backup)
	if err != nil {
		t.Fatalf("归档文件应存在: %v", err)
	}
	// 两份文件都不应超过“单条最大 ×2”太多（活动文件轮转后刚重开）。
	if activeInfo.Size() > lg.maxBytes*2 {
		t.Fatalf("活动文件未受界: %d", activeInfo.Size())
	}
	if backupInfo.Size() > lg.maxBytes*2 {
		t.Fatalf("归档文件未受界: %d", backupInfo.Size())
	}
}

// TestBoundedLogClampLongLine：超长单行必须被截断并带截断标记，避免一行吃满容量。
func TestBoundedLogClampLongLine(t *testing.T) {
	got := clampLogLine(strings.Repeat("x", boundedLogMaxLineBytes+5000))
	if len(got) <= boundedLogMaxLineBytes {
		t.Fatal("超长行未保留到上限长度")
	}
	if !strings.HasSuffix(got, "...[truncated]\n") {
		t.Fatalf("超长行缺少截断标记，结尾=%q", got[len(got)-32:])
	}
	short := clampLogLine("normal")
	if short != "normal" {
		t.Fatalf("短行不应被改动，got=%q", short)
	}
}

// TestBoundedLogRejectSymlink：目标若是符号链接必须拒绝写入（防日志写穿）。
// 无法创建符号链接的环境（如受限 Windows）跳过本用例。
func TestBoundedLogRejectSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	link := filepath.Join(dir, "link.log")
	if err := os.WriteFile(target, []byte("do-not-overwrite"), 0o600); err != nil {
		t.Fatalf("准备目标文件失败: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境无法创建符号链接，跳过: %v", err)
	}
	lg := &boundedLogger{path: link, maxBytes: boundedLogMaxBytes}
	if err := lg.appendBoundedLine("attacker"); err == nil {
		t.Fatal("写入符号链接应当被拒绝")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("读取目标文件失败: %v", err)
	}
	if string(data) != "do-not-overwrite" {
		t.Fatalf("符号链接目标被写穿: %q", string(data))
	}
}

// TestBoundedLogRejectDirectory：目标指向目录时必须拒绝。
func TestBoundedLogRejectDirectory(t *testing.T) {
	dir := t.TempDir()
	lg := &boundedLogger{path: dir, maxBytes: boundedLogMaxBytes}
	if err := lg.appendBoundedLine("x"); err == nil {
		t.Fatal("目标为目录时写入应当失败")
	}
}

// TestBoundedLogConcurrent：多 goroutine 并发追加同一文件不应产生竞态崩溃，
// 且文件总量仍被轮转约束在有限范围（race 由 go test -race 兜底）。
func TestBoundedLogConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conc.log")
	lg := &boundedLogger{path: path, maxBytes: 256}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = lg.appendBoundedLine("concurrent line payload")
			}
		}()
	}
	wg.Wait()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("并发写后活动文件应存在: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("并发写应触发轮转产生 .1: %v", err)
	}
}

// TestTailBoundedLog：tail 只返回尾部有限字节；不存在的文件返回空串且不报错。
func TestTailBoundedLog(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.log")
	if s, err := tailBoundedLog(missing, 64); err != nil || s != "" {
		t.Fatalf("不存在文件应返回空串，got=%q err=%v", s, err)
	}

	path := filepath.Join(dir, "tail.log")
	lg := &boundedLogger{path: path, maxBytes: boundedLogMaxBytes}
	for i := 0; i < 5; i++ {
		if err := lg.appendBoundedLine("0123456789ABCDEF"); err != nil {
			t.Fatalf("追加失败: %v", err)
		}
	}
	tail, err := tailBoundedLog(path, 20)
	if err != nil {
		t.Fatalf("tailBoundedLog 返回错误: %v", err)
	}
	if len(tail) > 20 {
		t.Fatalf("tail 超过请求上限: %d", len(tail))
	}
	if !strings.Contains(tail, "ABCDEF") {
		t.Fatalf("tail 应包含尾部内容，got=%q", tail)
	}
}
