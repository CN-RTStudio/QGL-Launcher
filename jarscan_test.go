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
		"fabric.mod.json":  "{}",
		"install.bat":      "@echo off\r\n",
		"setup.exe":        "MZ",
		"com/a/Main.class": "CAFEBABE",
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
		"fabric.mod.json":       "{}",
		"natives/windows/a.dll": "MZ",
		"bin/helper.exe":        "MZ",
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
		"fabric.mod.json":                  "{}",
		"META-INF/coremods/transformer.js": "var x=1;",
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
		"fabric.mod.json":         "{}",
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
