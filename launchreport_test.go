package main

// launchreport_test.go —— 启动总结报告内核测试。
//
// 验证的去敏要求：
//  1. -Dhttps.proxyHost=user:pass@1.2.3.4:8080/path 只留 "1.2.3.4:8080"；
//  2. -Dlog4j.* 标志被单独标记，不出现在 systemProps 计数；
//  3. @argfile 参数被识别（@argfile 绕过面）；
//  4. -Xmx2G / -Xms512M 归入 memory 并取最大值；
//  5. 环境变量：JAVA_TOOL_OPTIONS 等被隔离名单捕获、值不进入报告，
//     命名像密钥但未被拦截的变量被计数（NotableSecrets）；
//  6. classpath 只列 jar 文件名，路径/盘符不出现；
//  7. 退出码归类 ok / crash / nonZero。

import (
	"strings"
	"testing"
	"time"
)

func sampleReportInputs() (LaunchSnapshot, []string, []string, []string) {
	snap := buildLaunchSnapshot("1.20.4", `C:\Java\jdk17\bin\java.exe`, "17.0.9", "mojang", 2048, 12, true, false, 0)
	jvm := []string{
		"-Xmx2G",
		"-Xms512M",
		"-Dlog4j2.formatMsgNoLookups=true",
		"-Dhttps.proxyHost=user:pass@1.2.3.4:8080/path?x=1",
		"-Djava.awt.headless=true",
		"-classpath", "game.jar",
		"-Duser.home=" + `C:\Users\victim`,
		"@jvm-args.txt",
	}
	envs := []string{
		"JAVA_TOOL_OPTIONS=-Xmx4G",
		"PATH=C:\\bin",
		"MY_AUTH_TOKEN=abc123",
		"USERPROFILE=C:\\Users\\victim",
	}
	classpath := []string{
		`C:\minecraft\versions\1.20.4\1.20.4.jar`,
		`C:\mods\sodium-fabric.jar`,
		`C:\mods\forge.jar`,
		`C:\lib\natives`,
	}
	return snap, jvm, envs, classpath
}

func TestBuildLaunchReport_Memory(t *testing.T) {
	snap, jvm, envs, cp := sampleReportInputs()
	r := BuildLaunchReport(snap, time.Now(), jvm, envs, cp, 12345, 0)
	if r.JVM.MemoryMB != 2048 {
		t.Fatalf("期望 -Xmx2G 解析为 2048MB，得到 %d", r.JVM.MemoryMB)
	}
	if r.JVM.ArgCount != 9 {
		t.Fatalf("期望 9 个 JVM 参数，得到 %d（%+v）", r.JVM.ArgCount, r.JVM)
	}
}

func TestBuildLaunchReport_ProxySanitized(t *testing.T) {
	snap, jvm, envs, cp := sampleReportInputs()
	r := BuildLaunchReport(snap, time.Now(), jvm, envs, cp, 0, 0)
	if len(r.JVM.ProxyHosts) != 1 {
		t.Fatalf("期望 1 个代理 host，得到 %v", r.JVM.ProxyHosts)
	}
	got := r.JVM.ProxyHosts[0]
	if got != "1.2.3.4:8080" {
		t.Fatalf("代理值未去敏：%q", got)
	}
	for _, bad := range []string{"user", "pass", "/path", "?x=1"} {
		if strings.Contains(got, bad) {
			t.Fatalf("代理值残留敏感片段 %q: %q", bad, got)
		}
	}
}

func TestBuildLaunchReport_Log4jAndArgfile(t *testing.T) {
	snap, jvm, envs, cp := sampleReportInputs()
	r := BuildLaunchReport(snap, time.Now(), jvm, envs, cp, 0, 0)
	if !r.JVM.HasLog4jFlag {
		t.Fatal("log4j 标志未被标记")
	}
	if !r.JVM.HasArgfile {
		t.Fatal("@argfile 未被标记")
	}
	// log4j 参数不应计入 systemProps
	if r.JVM.SystemProps != 2 {
		t.Fatalf("期望 systemProps=2（headless、user.home），得到 %d", r.JVM.SystemProps)
	}
}

func TestBuildLaunchReport_EnvBlocked(t *testing.T) {
	snap, jvm, envs, cp := sampleReportInputs()
	r := BuildLaunchReport(snap, time.Now(), jvm, envs, cp, 0, 0)
	if r.Env.Count != 4 {
		t.Fatalf("期望 4 个环境变量，得到 %d", r.Env.Count)
	}
	if len(r.Env.BlockedNames) != 1 || r.Env.BlockedNames[0] != "JAVA_TOOL_OPTIONS" {
		t.Fatalf("隔离名单捕获错误: %v", r.Env.BlockedNames)
	}
	if r.Env.NotableSecrets != 1 {
		t.Fatalf("MY_AUTH_TOKEN 应计入 NotableSecrets，得到 %d", r.Env.NotableSecrets)
	}
	joined := strings.Join(r.Env.BlockedNames, "") + strings.Join(r.Env.BlockedNames, "")
	if strings.Contains(joined, "Xmx4G") {
		t.Fatal("环境变量值泄露进报告")
	}
}

func TestBuildLaunchReport_ClasspathNamesOnly(t *testing.T) {
	snap, jvm, envs, cp := sampleReportInputs()
	r := BuildLaunchReport(snap, time.Now(), jvm, envs, cp, 0, 0)
	if r.Classpath.JarCount != 3 {
		t.Fatalf("期望 3 个 jar，得到 %d", r.Classpath.JarCount)
	}
	if r.Classpath.NonJar != 1 {
		t.Fatalf("期望 1 个非 jar（natives），得到 %d", r.Classpath.NonJar)
	}
	for _, name := range r.Classpath.JarNames {
		if strings.ContainsAny(name, `:\/`) {
			t.Fatalf("classpath 泄露路径: %q", name)
		}
		if !strings.HasSuffix(name, ".jar") {
			t.Fatalf("classpath 只应列 jar: %q", name)
		}
	}
}

func TestBuildLaunchReport_ResultClass(t *testing.T) {
	snap := buildLaunchSnapshot("x", "y", "z", "mojang", 0, 0, true, false, 0)
	r0 := BuildLaunchReport(snap, time.Now(), nil, nil, nil, 0, 0)
	if r0.Result != "ok" {
		t.Fatalf("exit 0 应为 ok，得到 %s", r0.Result)
	}
	r1 := BuildLaunchReport(snap, time.Now(), nil, nil, nil, 0, -1073741819)
	if r1.Result != "crash" {
		t.Fatalf("负数退出码应为 crash，得到 %s", r1.Result)
	}
	r2 := BuildLaunchReport(snap, time.Now(), nil, nil, nil, 0, 1)
	if r2.Result != "nonZero" {
		t.Fatalf("exit 1 应为 nonZero，得到 %s", r2.Result)
	}
}

func TestParseMemoryMB(t *testing.T) {
	cases := map[string]int{
		"-Xmx512M":  512,
		"-Xmx2G":    2048,
		"-Xms256m":  256,
		"-Xmx1g":    1024,
		"-Xmx":      0,
		"-Xmxabc":   0,
		"-XX:+UseG1GC": 0,
		"-Xss1M":    0, // 栈大小不归入堆内存统计
	}
	for arg, want := range cases {
		if got := parseMemoryMB(arg); got != want {
			t.Errorf("parseMemoryMB(%q) = %d, want %d", arg, got, want)
		}
	}
}

func TestSanitizeProxyValue(t *testing.T) {
	cases := map[string]string{
		"user:pass@1.2.3.4:8080":        "1.2.3.4:8080",
		"http://proxy.example.com:3128":  "proxy.example.com:3128",
		"1.2.3.4:8080/path?x=1":          "1.2.3.4:8080",
		"":                              "(empty)",
		"   ":                           "(empty)",
	}
	for in, want := range cases {
		if got := sanitizeProxyValue(in); got != want {
			t.Errorf("sanitizeProxyValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnvNameLooksSecret(t *testing.T) {
	secrets := []string{"MY_AUTH_TOKEN", "DB_PASSWORD", "API_KEY", "AWS_ACCESS_KEY", "CUSTOM_SECRET"}
	for _, s := range secrets {
		if !envNameLooksSecret(s) {
			t.Errorf("%q 应被识别为密钥命名", s)
		}
	}
	ok := []string{"PATH", "USERPROFILE", "JAVA_HOME", "PWD"}
	for _, s := range ok {
		if envNameLooksSecret(s) {
			t.Errorf("%q 不应被识别为密钥命名", s)
		}
	}
}

func TestJvmArgCategory_Classify(t *testing.T) {
	if cat, _, _ := jvmArgCategory("-classpath"); cat != "classpath" {
		t.Fatalf("-classpath 应归 classpath，得到 %s", cat)
	}
	if cat, _, _ := jvmArgCategory("-Dfoo=bar"); cat != "sysprop" {
		t.Fatalf("-Dfoo 应归 sysprop，得到 %s", cat)
	}
	if cat, _, _ := jvmArgCategory("@args.txt"); cat != "argfile" {
		t.Fatalf("@args.txt 应归 argfile，得到 %s", cat)
	}
	if cat, _, _ := jvmArgCategory("-Dlog4j2.formatMsgNoLookups=true"); cat != "log4j" {
		t.Fatalf("log4j 标志应单独标记，得到 %s", cat)
	}
	if cat, _, _ := jvmArgCategory("-Xmx1G"); cat != "memory" {
		t.Fatalf("-Xmx1G 应归 memory，得到 %s", cat)
	}
	if cat, _, _ := jvmArgCategory("-server"); cat != "other" {
		t.Fatalf("-server 应归 other，得到 %s", cat)
	}
}

func TestReportSize_Bounded(t *testing.T) {
	snap, jvm, envs, cp := sampleReportInputs()
	r := BuildLaunchReport(snap, time.Now(), jvm, envs, cp, 0, 0)
	sz := ReportSize(r)
	if sz <= 0 || sz > reportMaxReportLen {
		t.Fatalf("ReportSize 越界: %d", sz)
	}
}
