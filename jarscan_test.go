package main

// jarscan_test.go 用内存 zip 构造各种形态的“Mod jar”，验证静态扫描的命中、
// 级别与阻断判定，确保不会把带本地库 / JarJar 的正常 Mod 误判为 critical。

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// buildJarInMemory 用给定的 名称->内容 映射在内存里拼一个 zip（即 jar）。
func buildJarInMemory(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("创建 zip 条目 %s 失败: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("写 zip 条目 %s 失败: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭 zip 失败: %v", err)
	}
	return buf.Bytes()
}

func findFinding(rep *JarScanReport, rule string) *JarFinding {
	for i := range rep.Findings {
		if rep.Findings[i].Rule == rule {
			return &rep.Findings[i]
		}
	}
	return nil
}

// 正常 Fabric Mod：带 fabric.mod.json、普通 class、一个本地库、一个嵌套 jar，
// 不应被判为阻断。
func TestJarScanCleanFabricMod(t *testing.T) {
	emptyJar := buildJarWithClasses(t, map[string][]byte{})
	data := buildJarWithClasses(t, map[string][]byte{
		"fabric.mod.json":        []byte(`{"id":"example"}`),
		"com/example/Main.class": []byte("CAFEBABE"),
		"natives/windows/x.dll":  []byte("MZ"),
		"META-INF/jars/dep.jar":  emptyJar,
		"META-INF/MANIFEST.MF":   []byte("Manifest-Version: 1.0\r\n\r\n"),
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描正常 Mod 不应报错: %v", err)
	}
	if rep.Blocked() {
		t.Fatalf("正常 Mod 不应被阻断，发现: %+v", rep.Findings)
	}
	if !rep.HasModMarker {
		t.Fatal("应当识别出 fabric.mod.json 标记")
	}
	if rep.NativeLibs != 1 || rep.NestedJars != 1 {
		t.Fatalf("本地库/嵌套 jar 计数错误: native=%d nested=%d", rep.NativeLibs, rep.NestedJars)
	}
	if findFinding(rep, "no-mod-marker") != nil {
		t.Fatal("有 Mod 标记时不应再报 no-mod-marker")
	}
}

// MANIFEST 声明 Premain-Class：JVM 代理入口，必须 warn。
func TestJarScanJvmAgentManifest(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"fabric.mod.json":      "{}",
		"com/a/Agent.class":    "CAFEBABE",
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nPremain-Class: com.a.Agent\r\n\r\n",
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	f := findFinding(rep, "jvm-agent-manifest")
	if f == nil {
		t.Fatal("应命中 jvm-agent-manifest")
	}
	if f.Severity != JarSeverityWarn {
		t.Fatalf("JVM 代理应为 warn，得到 %s", f.Severity)
	}
}

// 多行续行 + CRLF 的 MANIFEST 也要正确折叠出 Agent-Class。
func TestJarScanManifestContinuation(t *testing.T) {
	manifest := "Manifest-Version: 1.0\r\nAgent-Class: com.long\r\n .pkg.Evil\r\n\r\n"
	data := buildJarInMemory(t, map[string]string{
		"fabric.mod.json":      "{}",
		"META-INF/MANIFEST.MF": manifest,
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	f := findFinding(rep, "jvm-agent-manifest")
	if f == nil || !strings.Contains(f.Detail, "com.long.pkg.Evil") {
		t.Fatalf("续行折叠失败，发现: %+v", f)
	}
}

// 根目录放 .bat / .exe：critical，必须阻断。
func TestJarScanRootExecutableBlocked(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"fabric.mod.json":    "{}",
		"install.bat":        "@echo off\r\n",
		"setup.exe":          "MZ",
		"com/a/Main.class":   "CAFEBABE",
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if !rep.Blocked() {
		t.Fatal("根目录可执行脚本必须阻断")
	}
	if findFinding(rep, "root-executable") == nil {
		t.Fatal("应命中 root-executable 规则")
	}
}

// 子目录里的本地库不算“根目录可执行”，不阻断。
func TestJarScanNestedExeNotCritical(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"fabric.mod.json":        "{}",
		"natives/windows/a.dll":  "MZ",
		"bin/helper.exe":         "MZ",
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if rep.Blocked() {
		t.Fatal("子目录中的二进制不应判为 critical 阻断")
	}
}

// META-INF 下 Nashorn coremod 脚本应 warn。
func TestJarScanCoremodScript(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"fabric.mod.json":                       "{}",
		"META-INF/coremods/transformer.js":      "var x=1;",
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if findFinding(rep, "coremod-script") == nil {
		t.Fatal("应命中 coremod-script")
	}
}

// ModLauncher 转换服务应 warn。
func TestJarScanTransformerService(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"fabric.mod.json": "{}",
		"META-INF/services/cpw.mods.modlauncher.ITransformationService": "com.T",
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if findFinding(rep, "classloader-transform-service") == nil {
		t.Fatal("应命中 classloader-transform-service")
	}
}

// pack200 载体应 warn。
func TestJarScanPack200(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"fabric.mod.json": "{}",
		"com/a/Foo.class.pack.gz": "x",
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if findFinding(rep, "pack200-carrier") == nil {
		t.Fatal("应命中 pack200-carrier")
	}
}

// 有 class 却无任何 Mod 标记：warn。
func TestJarScanNoModMarker(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"com/unknown/X.class": "CAFEBABE",
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if f := findFinding(rep, "no-mod-marker"); f == nil || f.Severity != JarSeverityWarn {
		t.Fatalf("无 Mod 标记应 warn，得到 %+v", f)
	}
}

// 完全不是 zip：报错而不是放行。
func TestJarScanInvalidArchive(t *testing.T) {
	if _, err := scanJarBytes([]byte("this is not a jar at all")); err == nil {
		t.Fatal("非法 zip 必须返回错误")
	}
}

// Main-Class 仅 info，不阻断。
func TestJarScanMainClassInfo(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"Main.class":           "CAFEBABE",
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nMain-Class: Main\r\n\r\n",
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	f := findFinding(rep, "main-class")
	if f == nil || f.Severity != JarSeverityInfo {
		t.Fatalf("Main-Class 应为 info，得到 %+v", f)
	}
	if rep.Blocked() {
		t.Fatal("仅 Main-Class 不应阻断")
	}
}

// buildClassBytes 构造一个只含常量池 UTF8 项的最小合法 class 字节流，
// 供字节码行为启发式测试（魔数 + 版本 + 常量池计数 + 若干 UTF8 常量）。
func buildClassBytes(utf8s ...string) []byte {
	var b bytes.Buffer
	w := &b
	w.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE})
	w.Write([]byte{0, 0})       // minor
	w.Write([]byte{0, 52})     // major (Java 8)
	cpCount := len(utf8s) + 1
	w.Write([]byte{byte(cpCount >> 8), byte(cpCount)})
	for _, s := range utf8s {
		w.WriteByte(1) // CONSTANT_Utf8
		w.Write([]byte{byte(len(s) >> 8), byte(len(s))})
		w.WriteString(s)
	}
	return b.Bytes()
}

// buildJarWithClasses 用 class 字节（非字符串）构造 jar。
func buildJarWithClasses(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("创建 zip 条目 %s 失败: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("写 zip 条目 %s 失败: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭 zip 失败: %v", err)
	}
	return buf.Bytes()
}

// class 常量池含 Runtime+exec 应命中 warn 行为信号，但不阻断。
func TestJarScanBehaviorRuntimeExec(t *testing.T) {
	cls := buildClassBytes("java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
	data := buildJarWithClasses(t, map[string][]byte{
		"fabric.mod.json":        []byte(`{"id":"x"}`),
		"com/x/Evil.class":       cls,
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	f := findFinding(rep, "behavior-process-exec")
	if f == nil {
		t.Fatalf("应命中 Runtime.exec 行为信号，发现: %+v", rep.Findings)
	}
	if f.Severity != JarSeverityWarn {
		t.Fatalf("Runtime.exec 应为 warn，得到 %s", f.Severity)
	}
	if rep.Blocked() {
		t.Fatal("行为信号仅 warn，不应阻断")
	}
	if rep.ScannedClasses != 1 {
		t.Fatalf("应扫描 1 个 class，得到 %d", rep.ScannedClasses)
	}
}

// URLClassLoader 单独出现即命中（andAlso 为空）。
func TestJarScanBehaviorUrlClassLoader(t *testing.T) {
	cls := buildClassBytes("java/net/URLClassLoader", "<init>")
	data := buildJarWithClasses(t, map[string][]byte{"com/x/Loader.class": cls})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if findFinding(rep, "behavior-url-classloader") == nil {
		t.Fatalf("应命中 URLClassLoader 信号，发现: %+v", rep.Findings)
	}
}

// 干净 class（普通类名/方法名）不应命中任何行为规则。
func TestJarScanBehaviorCleanClass(t *testing.T) {
	cls := buildClassBytes("com/example/Main", "onInitialize", "()V")
	data := buildJarWithClasses(t, map[string][]byte{
		"fabric.mod.json":      []byte(`{"id":"clean"}`),
		"com/example/Main.class": cls,
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Rule, "behavior-") {
			t.Fatalf("干净 class 不应命中行为规则，却命中 %s", f.Rule)
		}
	}
}

// 同一行为规则跨多个 class 只报一次（ruleSeen 去重）。
func TestJarScanBehaviorRuleDedup(t *testing.T) {
	a := buildClassBytes("java/lang/Runtime", "exec")
	b := buildClassBytes("java/lang/Runtime", "exec", "another")
	data := buildJarWithClasses(t, map[string][]byte{
		"A.class": a,
		"B.class": b,
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	count := 0
	for _, f := range rep.Findings {
		if f.Rule == "behavior-process-exec" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("同一规则应只报一次，得到 %d 次", count)
	}
}

// 魔数不符的伪 class 不参与行为分析，也不影响扫描。
func TestJarScanBehaviorBogusMagicSkipped(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"NotClass.class": "CAFEBABE-not-real-bytes",
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if rep.ScannedClasses != 0 {
		t.Fatalf("魔数不符的条目不应计入已扫描 class，得到 %d", rep.ScannedClasses)
	}
}

// 嵌套 jar（JarJar）根部携带 .exe 必须被递归扫描发现并阻断，
// 且 finding 的条目路径带 “外层!/内层” 前缀。
func TestJarScanNestedRootExecutableBlocked(t *testing.T) {
	inner := buildJarInMemory(t, map[string]string{
		"evil.exe": "MZ",
	})
	outer := buildJarWithClasses(t, map[string][]byte{
		"fabric.mod.json":      []byte(`{"id":"outer"}`),
		"META-INF/jars/x.jar": inner,
	})
	rep, err := scanJarBytes(outer)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if !rep.Blocked() {
		t.Fatalf("嵌套 jar 根部 .exe 应触发阻断，发现: %+v", rep.Findings)
	}
	var hit bool
	for _, f := range rep.Findings {
		if f.Rule == "root-executable" &&
			strings.Contains(f.Entry, "META-INF/jars/x.jar") &&
			strings.HasSuffix(f.Entry, "evil.exe") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("应报告带嵌套前缀的 root-executable，发现: %+v", rep.Findings)
	}
}

// 损坏 / 非 zip 的嵌套条目只记 warn，不阻断整个 Mod（避免误伤）。
func TestJarScanNestedUnreadableNotBlocked(t *testing.T) {
	data := buildJarWithClasses(t, map[string][]byte{
		"fabric.mod.json":     []byte(`{"id":"ok"}`),
		"META-INF/jars/bad.jar": []byte("this is not a zip at all"),
	})
	rep, err := scanJarBytes(data)
	if err != nil {
		t.Fatalf("扫描报错: %v", err)
	}
	if rep.Blocked() {
		t.Fatalf("损坏的嵌套 jar 不应阻断整个 Mod: %+v", rep.Findings)
	}
	if findFinding(rep, "nested-unreadable") == nil {
		t.Fatalf("应记录 nested-unreadable warn，发现: %+v", rep.Findings)
	}
}
