package main

import (
	"testing"
)

func TestScanCmdline_NoLeaks(t *testing.T) {
	args := []string{"java", "-Xmx2G", "-cp", "libraries/*", "net.minecraft.client.Main", "--gameDir", ".minecraft"}
	if got := scanCmdlineForLeaks(args); len(got) != 0 {
		t.Fatalf("expected no leaks, got %v", got)
	}
}

func TestScanCmdline_AccessTokenAsProperty(t *testing.T) {
	args := []string{"java", "-DaccessToken=ABC123XYZ", "-cp", "x"}
	got := scanCmdlineForLeaks(args)
	if len(got) != 1 {
		t.Fatalf("want 1 leak, got %v", got)
	}
	if got[0].Kind != leakAccessToken || got[0].Index != 1 {
		t.Fatalf("bad hit: %+v", got[0])
	}
}

func TestScanCmdline_ClientToken(t *testing.T) {
	args := []string{"--clientToken=tok", "--gameDir", "x"}
	got := scanCmdlineForLeaks(args)
	if len(got) != 1 || got[0].Kind != leakClientToken {
		t.Fatalf("want client-token, got %v", got)
	}
}

func TestScanCmdline_PasswordKV(t *testing.T) {
	args := []string{"--password=hunter2"}
	if !cmdlineHasLeakedSecrets(args) {
		t.Fatal("password= must be flagged")
	}
}

func TestScanCmdline_SuffixKey(t *testing.T) {
	// -Dcustom.auth.sessionid=... 也应命中
	args := []string{"-Dcustom.auth.sessionid=sid-1"}
	got := scanCmdlineForLeaks(args)
	if len(got) != 1 || got[0].Kind != leakSessionID {
		t.Fatalf("want session-id by suffix, got %v", got)
	}
}

func TestScanCmdline_EmptyValueIgnored(t *testing.T) {
	args := []string{"-DaccessToken="}
	if got := scanCmdlineForLeaks(args); len(got) != 0 {
		t.Fatalf("empty value should not count, got %v", got)
	}
}

func TestScanCmdline_OrdinaryJarNotFlagged(t *testing.T) {
	// 裸参数/位置参数不应被当键扫
	args := []string{"minecraft.jar", "net.fabricmc.loader.impl.launch.knot.KnotClient"}
	if got := scanCmdlineForLeaks(args); len(got) != 0 {
		t.Fatalf("positional args must not be scanned as keys: %v", got)
	}
}
