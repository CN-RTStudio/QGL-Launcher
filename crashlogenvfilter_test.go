package main

import (
	"strings"
	"testing"
)

func TestFilterCrashLogEnv_Allowlist(t *testing.T) {
	in := []string{
		"PATH=C:\\Windows",
		"HOMEPATH=\\Users\\test",
		"UNKNOWN_X=1",
	}
	got := FilterCrashLogEnv(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %v", got)
	}
}

func TestFilterCrashLogEnv_BlocklistRedacts(t *testing.T) {
	in := []string{
		"MINECRAFT_ACCESS_TOKEN=abc123",
		"MOJANG_SESSION=xyz",
		"HTTP_PROXY=http://user:pass@host:8080",
	}
	got := FilterCrashLogEnv(in)
	for _, kv := range got {
		if strings.Contains(kv, "abc123") || strings.Contains(kv, "xyz") || strings.Contains(kv, "user:pass") {
			t.Fatalf("secret leaked: %s", kv)
		}
		if !strings.HasSuffix(kv, "=<redacted>") {
			t.Fatalf("expected redacted, got %s", kv)
		}
	}
}

func TestFilterCrashLogEnv_BadForm(t *testing.T) {
	got := FilterCrashLogEnv([]string{"novalue", "=novalue", "PATH=/ok"})
	if len(got) != 1 {
		t.Fatalf("expected 1 valid entry, got %v", got)
	}
}

func TestFilterCrashLogEnv_KeepJavaHome(t *testing.T) {
	in := []string{"JAVA_HOME=C:\\jdk"}
	got := FilterCrashLogEnv(in)
	if len(got) != 1 || got[0] != "JAVA_HOME=C:\\jdk" {
		t.Fatalf("JAVA_HOME must pass through, got %v", got)
	}
}
