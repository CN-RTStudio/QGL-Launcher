package main

import (
	"testing"
)

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
