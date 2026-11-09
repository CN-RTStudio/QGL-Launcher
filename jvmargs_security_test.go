package main

import "testing"

func TestFilterUntrustedJvmArgsBlocksCodeExecFlags(t *testing.T) {
	in := []string{
		"-javaagent:evil.jar",
		"-XX:OnError=calc.exe",
		"-XX:OnOutOfMemoryError=cmd /c calc",
		"-agentlib:jdwp=transport=dt_socket,server=y,address=*:5005",
		"-agentpath:C:\\evil.dll",
		"-XX:VMOptionsFile=C:\\opts.txt",
		"-XXaltjvm=D:\\fakejvm",
		"-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005",
	}
	safe, blocked, truncated := filterUntrustedJvmArgs(in)
	if len(safe) != 0 {
		t.Fatalf("expected no safe args, got %v", safe)
	}
	if len(blocked) != len(in) {
		t.Fatalf("expected %d blocked flags, got %d: %v", len(in), len(blocked), blocked)
	}
	if truncated {
		t.Fatal("truncated should be false for small list")
	}
}

func TestFilterUntrustedJvmArgsKeepsOfficialFlags(t *testing.T) {
	in := []string{
		"-Djava.library.path=C:\\mc\\natives",
		"-Dorg.lwjgl.librarypath=C:\\mc\\natives",
		"-cp", "lib1.jar;lib2.jar",
		"--add-opens", "java.base/java.lang=ALL-UNNAMED",
		"--add-exports", "java.base/sun.nio.ch=ALL-UNNAMED",
		"--add-modules", "jdk.crypto.cryptoki",
		"--enable-native-access=ALL-UNNAMED",
		"-p", "C:\\mc\\libraries",
		"--module-path=C:\\mc\\libraries",
		"-Xmx4G", "-Xms1G", "-Xss2M",
		"-XX:+UseG1GC", "-XX:G1HeapRegionSize=32M",
		"-Dfabric.loader.game.version=1.21",
	}
	safe, blocked, _ := filterUntrustedJvmArgs(in)
	if len(blocked) != 0 {
		t.Fatalf("official flags must not be blocked: %v", blocked)
	}
	if len(safe) != len(in) {
		t.Fatalf("expected all %d args kept, got %d: %v", len(in), len(safe), safe)
	}
}

func TestFilterUntrustedJvmArgsDropsSeparateOperand(t *testing.T) {
	// "-jar evil.jar"、"-m module/main" 的操作数是独立 token，必须一并丢弃，
	// 否则操作数会被当成一个孤立的 JVM 参数传给 java。
	in := []string{"-Dok=1", "-jar", "evil.jar", "-Xmx2G", "-m", "evil/evil.Main", "-Dtail=1"}
	safe, blocked, _ := filterUntrustedJvmArgs(in)
	if len(blocked) != 2 || blocked[0] != "-jar" || blocked[1] != "-m" {
		t.Fatalf("unexpected blocked list: %v", blocked)
	}
	want := []string{"-Dok=1", "-Xmx2G", "-Dtail=1"}
	if len(safe) != len(want) {
		t.Fatalf("expected %v, got %v", want, safe)
	}
	for i := range want {
		if safe[i] != want[i] {
			t.Fatalf("safe[%d]=%q, want %q", i, safe[i], want[i])
		}
	}
}

func TestFilterUntrustedJvmArgsCaseInsensitive(t *testing.T) {
	in := []string{"-JAVAAGENT:Evil.JAR", "-xx:onerror=calc", "-XrUnJdWP:x"}
	safe, blocked, _ := filterUntrustedJvmArgs(in)
	if len(safe) != 0 || len(blocked) != 3 {
		t.Fatalf("case-insensitive match failed: safe=%v blocked=%v", safe, blocked)
	}
}

func TestFilterUntrustedJvmArgsTruncates(t *testing.T) {
	in := make([]string, 0, maxUntrustedJvmArgs+10)
	for i := 0; i < maxUntrustedJvmArgs+10; i++ {
		in = append(in, "-Dbenchmark.prop=value")
	}
	safe, _, truncated := filterUntrustedJvmArgs(in)
	if !truncated {
		t.Fatal("expected truncated=true when exceeding maxUntrustedJvmArgs")
	}
	if len(safe) != maxUntrustedJvmArgs {
		t.Fatalf("expected exactly %d kept, got %d", maxUntrustedJvmArgs, len(safe))
	}
}

func TestIsDangerousJvmFlagBoundaries(t *testing.T) {
	bad := []string{
		"-javaagent", "-javaagent:a.jar", "-JAVAAGENT:x",
		"-xx:onerror", "-xx:onerror=cmd",
		"-jar", "-m", "--module", "-xrunjdwp:x",
	}
	for _, b := range bad {
		if !isDangerousJvmFlag(b) {
			t.Errorf("expected dangerous: %q", b)
		}
	}
	good := []string{"-xmx2g", "-xx:+useg1gc", "-djava.library.path=x", "-xss1m", "--module-path=x"}
	for _, g := range good {
		if isDangerousJvmFlag(g) {
			t.Errorf("expected safe: %q", g)
		}
	}
}

// TestJvmArgThreatBlocksArgumentFiles 覆盖本轮主漏洞：JDK 9+ 的 @argfile 响应
// 文件会在命令行解析前把文件内容展开成任意参数，必须无条件拦截，否则可借
// 文件内的 -javaagent 完全绕过前缀黑名单。
func TestJvmArgThreatBlocksArgumentFiles(t *testing.T) {
	bad := []string{
		"@C:\\Users\\victim\\evil.txt",
		"@opts",
		"@./rel/args",
		"@", // 裸 @ 也拒绝，fail-closed
	}
	for _, b := range bad {
		dangerous, consumes := jvmArgThreat(b)
		if !dangerous {
			t.Errorf("argument file must be dangerous: %q", b)
		}
		if consumes {
			t.Errorf("@argfile 不应吞掉下一 token（路径在同一参数内）: %q", b)
		}
	}
}

func TestFilterUntrustedJvmArgsBlocksArgumentFile(t *testing.T) {
	// 即使攻击者在 @file 前后塞满正常参数，响应文件参数本身也必须被剔除，
	// 且它不带操作数，不会误伤紧随其后的普通参数。
	in := []string{"-Xmx4G", "@evil.txt", "-Dkeep=1"}
	safe, blocked, _ := filterUntrustedJvmArgs(in)
	if len(blocked) != 1 || blocked[0] != "@evil.txt" {
		t.Fatalf("expected only @evil.txt blocked, got %v", blocked)
	}
	want := []string{"-Xmx4G", "-Dkeep=1"}
	if len(safe) != len(want) || safe[0] != want[0] || safe[1] != want[1] {
		t.Fatalf("expected %v, got %v", want, safe)
	}
}

// TestJvmArgThreatBlocksBytecodeVerificationBypass 覆盖关闭字节码校验的两种
// 等价写法，它们让被篡改的 class 无需通过校验即可加载执行。
func TestJvmArgThreatBlocksBytecodeVerificationBypass(t *testing.T) {
	bad := []string{
		"-noverify", "-NOVERIFY",
		"-Xverify:none", "-xverify:none",
		"-Xverify=none", "-xverify=none",
	}
	for _, b := range bad {
		if dangerous, _ := jvmArgThreat(b); !dangerous {
			t.Errorf("verification bypass must be dangerous: %q", b)
		}
	}
}

// TestJvmArgThreatBlocksDynamicAgentLoading 覆盖 JDK 21 动态 attach 门槛：
// 显式 +EnableDynamicAgentLoading 会放行运行期 agent 注入。
func TestJvmArgThreatBlocksDynamicAgentLoading(t *testing.T) {
	bad := []string{
		"-XX:+EnableDynamicAgentLoading",
		"-xx:+enabledynamicagentloading",
	}
	for _, b := range bad {
		if dangerous, _ := jvmArgThreat(b); !dangerous {
			t.Errorf("dynamic agent loading must be dangerous: %q", b)
		}
	}
	// 关闭动态加载是安全姿态，不应误杀。
	if dangerous, _ := jvmArgThreat("-XX:-EnableDynamicAgentLoading"); dangerous {
		t.Error("disabling dynamic agent loading must be safe")
	}
}

// TestJvmArgThreatSourceLaunchConsumesOperand 覆盖单文件源码启动：
// “--source <ver> <File.java>” 里 --source 的操作数是独立 token，要一并丢弃；
// 同 token 的 “--source=21” 只吞自身。
func TestJvmArgThreatSourceLaunchConsumesOperand(t *testing.T) {
	if dangerous, consumes := jvmArgThreat("--source"); !dangerous || !consumes {
		t.Fatalf("bare --source must be dangerous and consume operand, got %v %v", dangerous, consumes)
	}
	if dangerous, consumes := jvmArgThreat("--source=21"); !dangerous || consumes {
		t.Fatalf("--source=21 must be dangerous without consuming next token, got %v %v", dangerous, consumes)
	}
	in := []string{"-Xmx1G", "--source", "21", "evil.java", "-Dtail=1"}
	safe, blocked, _ := filterUntrustedJvmArgs(in)
	if len(blocked) != 1 || blocked[0] != "--source" {
		t.Fatalf("expected only --source blocked, got %v", blocked)
	}
	want := []string{"-Xmx1G", "evil.java", "-Dtail=1"}
	if len(safe) != len(want) {
		t.Fatalf("operand 21 should be dropped, got %v", safe)
	}
}

// TestJvmArgThreatNearMissPrefixesSafe 确保前缀匹配是精确的：只认
// flag 精确相等或 flag:/flag= 连接，不允许 “-javaagentxxx” 这类前缀子串误判，
// 同时校验若干外形相近但实为普通性能参数的写法被正常放行。
func TestJvmArgThreatNearMissPrefixesSafe(t *testing.T) {
	safe := []string{
		"-javaagentless",
		"-agentlibname",
		"-xxaltjvmsuffix",
		"--module-path=C:\\mc\\lib",
		"-p", // 注意：-p 不是危险项（危险的是 -m/--module），不得误杀
		"-djava.net.preferIPv4Stack=true",
	}
	for _, s := range safe {
		if dangerous, _ := jvmArgThreat(s); dangerous {
			t.Errorf("near-miss should be safe: %q", s)
		}
	}
}

// TestClassifyUntrustedJvmArgReasons 验证带原因版本对各类威胁给出稳定原因码，
// 供安全审计日志聚合使用；普通参数返回空原因。
func TestClassifyUntrustedJvmArgReasons(t *testing.T) {
	cases := []struct {
		arg       string
		reason    string
		dangerous bool
	}{
		{"@evil.txt", "argument-file", true},
		{"-noverify", "noverify", true},
		{"-javaagent:a.jar", "javaagent", true},
		{"-XX:+EnableDynamicAgentLoading", "dynamic-agent", true},
		{"-jar", "main-entry", true},
		{"-Xmx4G", "", false},
	}
	for _, c := range cases {
		reason, dangerous, _ := classifyUntrustedJvmArg(c.arg)
		if dangerous != c.dangerous || reason != c.reason {
			t.Errorf("classify(%q)=(%q,%v), want reason=%q dangerous=%v", c.arg, reason, dangerous, c.reason, c.dangerous)
		}
	}
}

