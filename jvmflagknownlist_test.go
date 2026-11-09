package main

import (
	"strings"
	"testing"
)

func TestAuditJvmFlags_Block(t *testing.T) {
	in := []string{"-Xmx2G", "-javaagent:evil.jar", "-agentlib:jdwp=transport=dt_socket", "net.minecraft.client.Main"}
	blocked, passed := AuditJvmFlags(in)
	if len(blocked) != 2 {
		t.Fatalf("blocked = %v", blocked)
	}
	for _, p := range passed {
		if strings.HasPrefix(p, "-javaagent") || strings.HasPrefix(p, "-agentlib") {
			t.Fatalf("leaked blocked flag: %s", p)
		}
	}
}

func TestAuditJvmFlags_Pass(t *testing.T) {
	in := []string{"-Xmx4G", "-XX:+UseG1GC", "-Xms1G"}
	blocked, passed := AuditJvmFlags(in)
	if len(blocked) != 0 {
		t.Fatalf("should pass: %v", blocked)
	}
	if len(passed) != 3 {
		t.Fatalf("passed = %v", passed)
	}
}

func TestIsKnownJvmFlag(t *testing.T) {
	if !IsKnownJvmFlag("-Xmx2G") {
		t.Fatal("-Xmx should be known")
	}
	if IsKnownJvmFlag("-javaagent:x") {
		t.Fatal("-javaagent must be unknown")
	}
	if !IsKnownJvmFlag("net.minecraft.client.Main") {
		t.Fatal("main class arg should pass")
	}
}

func TestFilterJvmFlags(t *testing.T) {
	in := []string{"-Xmx2G", "-javaagent:x.jar", "-Dfoo=bar"}
	got := FilterJvmFlags(in)
	for _, g := range got {
		if strings.HasPrefix(g, "-javaagent") {
			t.Fatal("javaagent must be filtered")
		}
	}
}

func TestErrBlockedJvmFlags(t *testing.T) {
	if ErrBlockedJvmFlags(nil) != nil {
		t.Fatal("empty must be nil")
	}
	if ErrBlockedJvmFlags([]string{"-x"}) == nil {
		t.Fatal("non-empty must error")
	}
}
