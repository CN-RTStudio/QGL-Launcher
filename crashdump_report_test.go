package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderCrashDumpSummary(t *testing.T) {
	s := CrashDumpSummary{
		Kind: "hs_err", FileName: "hs_err_pid1.log",
		Description: "Tesselating", Exception: "java.lang.X: boom",
		Problematic: "[a.dll+0x1]", CausedBy: []string{"java.lang.Y: y"},
		Frames: []string{"at A.a(A.java:1)", "at B.b(B.java:2)", "at C.c(C.java:3)"},
	}
	out := renderCrashDumpSummary(s)
	for _, want := range []string{"hs_err_pid1.log", "Tesselating", "boom", "[a.dll+0x1]", "Caused by", "A.java:1"} {
		if !strings.Contains(out, want) {
			t.Errorf("摘要缺少 %q: %s", want, out)
		}
	}
	empty := CrashDumpSummary{Kind: "minecraft", FileName: "c.txt"}
	if !strings.Contains(renderCrashDumpSummary(empty), "未提取到关键信息") {
		t.Fatal("空摘要应给出兜底说明")
	}
	tr := CrashDumpSummary{Kind: "minecraft", FileName: "c.txt", Truncated: true}
	if !strings.Contains(renderCrashDumpSummary(tr), "截断") {
		t.Fatal("截断摘要应标注")
	}
}

// writeDumpFile 在 dir 下写一个普通崩溃文件并设置 mtime。
func writeDumpFile(t *testing.T, dir, name, content string, mod time.Time) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPickLatestDumpEntry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// 两个合法候选，取 mtime 最新者。
	writeDumpFile(t, dir, "crash-old.txt", sampleMinecraftReport, now.Add(-2*time.Hour))
	writeDumpFile(t, dir, "crash-new.txt", sampleMinecraftReport, now.Add(-time.Minute))
	// 前缀/后缀不符、目录都应被忽略。
	writeDumpFile(t, dir, "ignore.txt", "x", now)
	if err := os.MkdirAll(filepath.Join(dir, "crash-dir.txt"), 0o700); err != nil {
		t.Fatal(err)
	}
	// 早于 notBefore 的旧文件被过滤。
	notBefore := now.Add(-time.Hour)
	path, name, _, ok := pickLatestDumpEntry(dir, "crash-", ".txt", notBefore)
	if !ok {
		t.Fatal("应选到候选")
	}
	if name != "crash-new.txt" {
		t.Fatalf("应选最新候选 crash-new.txt, got %q (%s)", name, path)
	}
	// 不存在的目录返回 false。
	if _, _, _, ok := pickLatestDumpEntry(filepath.Join(dir, "nope"), "crash-", ".txt", notBefore); ok {
		t.Fatal("不存在目录应返回 false")
	}
}

func TestCollectLatestCrashDumpPrefersMinecraft(t *testing.T) {
	gameDir := t.TempDir()
	now := time.Now()
	writeDumpFile(t, filepath.Join(gameDir, "crash-reports"),
		"crash-2026-10-04_12.00.00-client.txt", sampleMinecraftReport, now.Add(-time.Minute))
	writeDumpFile(t, gameDir, "hs_err_pid1.log", sampleHsErr, now.Add(-time.Minute))

	s, ok := collectLatestCrashDump(gameDir, now.Add(-2*time.Hour))
	if !ok {
		t.Fatal("应收集到崩溃产物")
	}
	if s.Kind != "minecraft" {
		t.Fatalf("结构化 minecraft 报告应优先于 hs_err, got %s", s.Kind)
	}
	if !strings.Contains(s.Description, "Tesselating") {
		t.Fatalf("报告内容解析错误: %+v", s)
	}
}

func TestCollectLatestCrashDumpFallbackHsErr(t *testing.T) {
	gameDir := t.TempDir()
	now := time.Now()
	writeDumpFile(t, gameDir, "hs_err_pid9.log", sampleHsErr, now.Add(-time.Minute))
	s, ok := collectLatestCrashDump(gameDir, now.Add(-2*time.Hour))
	if !ok || s.Kind != "hs_err" {
		t.Fatalf("无 minecraft 报告时应回退 hs_err, ok=%v kind=%s", ok, s.Kind)
	}
	if s.Problematic != "[nvoglv64.dll+0x12ab34]" {
		t.Fatalf("frame 提取错误: %q", s.Problematic)
	}
}

func TestCollectLatestCrashDumpSkipsOversizeAndFallsBack(t *testing.T) {
	gameDir := t.TempDir()
	now := time.Now()
	// 超大 minecraft 报告（稀疏文件，真实 size 超上限）：应被有界读取拒绝并审计放弃，
	// 随后回退到合法的 hs_err。
	bigDir := filepath.Join(gameDir, "crash-reports")
	if err := os.MkdirAll(bigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bigPath := filepath.Join(bigDir, "crash-huge.txt")
	f, err := os.OpenFile(bigPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(crashDumpMaxBytes + 64); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("---- Minecraft Crash Report ----\n"), 0); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chtimes(bigPath, now.Add(-time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	writeDumpFile(t, gameDir, "hs_err_pid2.log", sampleHsErr, now.Add(-time.Minute))

	s, ok := collectLatestCrashDump(gameDir, now.Add(-2*time.Hour))
	if !ok {
		t.Fatal("超大 minecraft 被跳过后应回退到 hs_err")
	}
	if s.Kind != "hs_err" {
		t.Fatalf("应回退 hs_err, got %s", s.Kind)
	}
}

func TestCollectLatestCrashDumpStaleIgnored(t *testing.T) {
	gameDir := t.TempDir()
	now := time.Now()
	// 报告时间早于进程启动时间 -> 属于上一局，忽略。
	writeDumpFile(t, filepath.Join(gameDir, "crash-reports"),
		"crash-stale.txt", sampleMinecraftReport, now.Add(-3*time.Hour))
	if _, ok := collectLatestCrashDump(gameDir, now.Add(-30*time.Minute)); ok {
		t.Fatal("陈旧崩溃报告应被时间过滤忽略")
	}
}

// crash-reports 子目录本身被做成指向游戏目录外的符号链接时，枚举会落到外部目录。
// 该子目录必须先被拒绝（非符号链接、解析后仍在 gameDir 内），不能跟随去外部读文件。
func TestCollectLatestCrashDumpSymlinkedReportsDir(t *testing.T) {
	gameDir := t.TempDir()
	outside := t.TempDir()
	now := time.Now()
	// 在外部目录放一个看似合法的崩溃报告。
	writeDumpFile(t, outside, "crash-evil.txt", sampleMinecraftReport, now.Add(-time.Minute))
	linkDir := filepath.Join(gameDir, "crash-reports")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Skipf("当前环境不允许创建符号链接，跳过: %v", err)
	}
	if dir, ok := resolveCrashReportsDir(gameDir); ok {
		t.Fatalf("符号链接 crash-reports 必须被拒绝, got dir=%q", dir)
	}
	if _, ok := collectLatestCrashDump(gameDir, now.Add(-2*time.Hour)); ok {
		t.Fatal("不应跟随符号链接 crash-reports 去外部目录收集崩溃报告")
	}
}

// 真实目录与“尚不存在”的 crash-reports 都应正常解析：前者用于枚举，后者在
// 解析到已存在的 gameDir 祖先时也应放行（随后枚举为空），不能误伤正常启动。
func TestResolveCrashReportsDirNormalAndMissing(t *testing.T) {
	gameDir := t.TempDir()
	// 尚不存在：按“已存在祖先”解析，应放行。
	dir, ok := resolveCrashReportsDir(gameDir)
	if !ok {
		t.Fatal("尚不存在的 crash-reports 应可解析（枚举为空），不应被拒绝")
	}
	if filepath.Base(dir) != "crash-reports" {
		t.Fatalf("返回目录名异常: %q", dir)
	}
	if err := os.MkdirAll(filepath.Join(gameDir, "crash-reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	if dir, ok = resolveCrashReportsDir(gameDir); !ok {
		t.Fatal("真实 crash-reports 目录应放行")
	} else if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("放行的目录应真实存在: %v", statErr)
	}
}
