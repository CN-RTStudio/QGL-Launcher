package main

import (
	"path/filepath"
	"strings"
	"testing"
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
		"# C  [nvoglv64.dll+0x1]":       "[nvoglv64.dll+0x1]",
		"# J 1234 java.lang.Thread.run": "1234 java.lang.Thread.run",
		"# j  java.lang.Object.wait()":  "java.lang.Object.wait()",
		"# v  ~StubRoutines::call_stub": "~StubRoutines::call_stub",
		"# JRE version: foo":            "",
		"random":                        "",
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
