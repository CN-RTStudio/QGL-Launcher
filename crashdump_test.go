package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClassifyCrashDump(t *testing.T) {
	if k := classifyCrashDump("---- Minecraft Crash Report ----\nblah"); k != "minecraft" {
		t.Fatalf("minecraft 报告分类错误: %q", k)
	}
	if k := classifyCrashDump("# A fatal error has been detected by the Java Runtime Environment:"); k != "hs_err" {
		t.Fatalf("hs_err 分类错误: %q", k)
	}
	if k := classifyCrashDump("# EXCEPTION_ACCESS_VIOLATION"); k != "hs_err" {
		t.Fatalf("EXCEPTION 信号应分类为 hs_err: %q", k)
	}
	if k := classifyCrashDump("random log line\nnothing"); k != "" {
		t.Fatalf("未知产物应返回空: %q", k)
	}
}

func TestSafeCrashName(t *testing.T) {
	// 任何目录成分都必须被剥离，只留基名。
	if got := safeCrashName(filepath.Join("..", "..", "etc", "crash-1.txt")); got != "crash-1.txt" {
		t.Fatalf("目录成分未剥离: %q", got)
	}
	if got := safeCrashName("crash-1.txt"); got != "crash-1.txt" {
		t.Fatalf("合法基名被改写: %q", got)
	}
	// 危险文件名词法被收敛（控制字符 / 保留名等），不返回路径分隔符。
	got := safeCrashName("crash-1:aux?.txt")
	if strings.ContainsAny(got, `/\:*?"<>|`) {
		t.Fatalf("收敛后仍含危险字符: %q", got)
	}
}

func TestLooksLikeJavaException(t *testing.T) {
	good := []string{
		"java.lang.IllegalStateException: Already tesselating!",
		"cpw.mods.fml.common.LoaderException: java.lang.NoClassDefFoundError: Foo",
		"net.minecraftforge.fml.LoadingFailedException: ...",
	}
	for _, g := range good {
		if !looksLikeJavaException(g) {
			t.Errorf("应判为异常: %q", g)
		}
	}
	bad := []string{
		"",
		"-- Header --",
		"at net.minecraft.client.Minecraft.run(Minecraft.java:123)",
		"just a sentence without qualified type",
	}
	for _, b := range bad {
		if looksLikeJavaException(b) {
			t.Errorf("不应判为异常: %q", b)
		}
	}
}

func TestAppendUnique(t *testing.T) {
	var l []string
	l = appendUnique(l, "a", 2)
	l = appendUnique(l, "a", 2) // 去重
	l = appendUnique(l, "b", 2)
	l = appendUnique(l, "c", 2) // 超上限忽略
	if len(l) != 2 || l[0] != "a" || l[1] != "b" {
		t.Fatalf("去重/上限行为错误: %v", l)
	}
	if got := appendUnique(nil, "   ", 3); len(got) != 0 {
		t.Fatal("空白串不应加入")
	}
}

const sampleMinecraftReport = `---- Minecraft Crash Report ----
// Ouch.

Time: 2026-10-04 12:00:00
Description: Tesselating block model

java.lang.IllegalStateException: Already tesselating!
	at net.minecraft.client.renderer.block.model.BakedQuad.build(BakedQuad.java:42)
	at net.minecraft.client.renderer.BlockModelRenderer.render(BlockModelRenderer.java:88)
	at net.minecraft.client.renderer.RenderGlobal.render(RenderGlobal.java:501)
Caused by: java.lang.NullPointerException
	at com.example.Mod.foo(Mod.java:7)
Caused by: java.lang.RuntimeException: init failed
	at com.example.Mod.bar(Mod.java:9)

-- System Details --
Minecraft Version: 1.20.1
Operating System: Windows 10 (amd64)
`

func TestParseMinecraftCrash(t *testing.T) {
	lines, truncated := scanCrashLines([]byte(sampleMinecraftReport))
	if truncated {
		t.Fatal("正常样例不应标记截断")
	}
	s := parseMinecraftCrash(lines)
	if s.Description != "Tesselating block model" {
		t.Fatalf("Description 提取错误: %q", s.Description)
	}
	if !strings.Contains(s.Exception, "IllegalStateException") {
		t.Fatalf("顶层异常提取错误: %q", s.Exception)
	}
	if len(s.CausedBy) != 2 {
		t.Fatalf("应有两条 Caused by, got %d: %v", len(s.CausedBy), s.CausedBy)
	}
	if len(s.Frames) < 3 {
		t.Fatalf("应收集至少 3 帧, got %d", len(s.Frames))
	}
	// System Details 之后的环境噪声不应进入帧（at 帧应停在该段之前）。
	for _, f := range s.Frames {
		if strings.Contains(f, "Minecraft Version") {
			t.Fatal("System Details 噪声误入栈帧")
		}
	}
}

const sampleHsErr = `#
# A fatal error has been detected by the Java Runtime Environment:
#
#  EXCEPTION_ACCESS_VIOLATION (0xc0000005) at pc=0x00007ff, ip=0x0000000
#
# JRE version: OpenJDK Runtime Environment (17.0.9)
# Java VM: OpenJDK 64-Bit Server VM
#
# Problematic frame:
# C  [nvoglv64.dll+0x12ab34]
#
# Core dump will be written.
#
#  Internal Error (os_windows_x86.cpp:123), pid=1234, tid=99
#
# J 1234  java.lang.Thread.run()
# j  java.lang.Object.wait()
# v  ~StubRoutines::call_stub
# V  [libjvm.dll+0x11]
siginfo: EXCEPTION_ACCESS_VIOLATION
Register to memory mapping:
RAX=0x0
`

func TestHsFrame(t *testing.T) {
	cases := map[string]string{
		"# C  [nvoglv64.dll+0x1]":      "[nvoglv64.dll+0x1]",
		"# J 1234 java.lang.Thread.run":  "1234 java.lang.Thread.run",
		"# j  java.lang.Object.wait()":   "java.lang.Object.wait()",
		"# v  ~StubRoutines::call_stub": "~StubRoutines::call_stub",
		"# JRE version: foo":               "",
		"random":                           "",
	}
	for in, want := range cases {
		if got := hsFrame(in); got != want {
			t.Errorf("hsFrame(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseHsErrCrash(t *testing.T) {
	lines, truncated := scanCrashLines([]byte(sampleHsErr))
	if truncated {
		t.Fatal("正常样例不应标记截断")
	}
	s := parseHsErrCrash(lines)
	if s.Problematic != "[nvoglv64.dll+0x12ab34]" {
		t.Fatalf("Problematic frame 提取错误: %q", s.Problematic)
	}
	if !strings.Contains(s.Exception, "EXCEPTION_ACCESS_VIOLATION") {
		t.Fatalf("异常信号提取错误: %q", s.Exception)
	}
	if !strings.Contains(s.InternalError, "os_windows_x86.cpp:123") {
		t.Fatalf("Internal Error 提取错误: %q", s.InternalError)
	}
	// siginfo 之后是寄存器噪声，RAX 行不应进帧。
	if len(s.Frames) == 0 {
		t.Fatal("应收集到 Problematic 之前/其它 # 帧")
	}
}

func TestParseCrashDumpDispatch(t *testing.T) {
	if s, ok := parseCrashDump("crash-2026-10-04_12.00.00-client.txt", []byte(sampleMinecraftReport)); !ok || s.Kind != "minecraft" {
		t.Fatalf("minecraft 端到端解析失败 ok=%v kind=%s", ok, s.Kind)
	}
	if s, ok := parseCrashDump("hs_err_pid1234.log", []byte(sampleHsErr)); !ok || s.Kind != "hs_err" || s.FileName == "" {
		t.Fatalf("hs_err 端到端解析失败 ok=%v", ok)
	}
	if _, ok := parseCrashDump("x.txt", []byte("nothing useful")); ok {
		t.Fatal("未知产物应返回 false")
	}
}

func TestScanCrashLinesTruncation(t *testing.T) {
	// 超长单行被截断并标记。
	long := strings.Repeat("A", crashDumpLineMaxBytes+100)
	if _, truncated := scanCrashLines([]byte(long)); !truncated {
		t.Fatal("超长单行应标记截断")
	}
	// 行数超上限标记截断。
	var b strings.Builder
	for i := 0; i < crashDumpMaxLines+50; i++ {
		b.WriteString("line\n")
	}
	lines, truncated := scanCrashLines([]byte(b.String()))
	if !truncated {
		t.Fatal("超行数应标记截断")
	}
	if len(lines) != crashDumpMaxLines {
		t.Fatalf("应只保留 %d 行, got %d", crashDumpMaxLines, len(lines))
	}
}

func TestRenderCrashDumpSummary(t *testing.T) {
	s := CrashDumpSummary{
		Kind: "hs_err", FileName: "hs_err_pid1.log",
		Description: "Tesselating", Exception: "java.lang.X: boom",
		Problematic: "[a.dll+0x1]", CausedBy: []string{"java.lang.Y: y"},
		Frames:      []string{"at A.a(A.java:1)", "at B.b(B.java:2)", "at C.c(C.java:3)"},
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
