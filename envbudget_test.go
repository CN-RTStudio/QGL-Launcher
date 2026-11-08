package main

import (
	"strings"
	"testing"
)

func TestAuditEnvBudget(t *testing.T) {
	lim := defaultEnvLimits()

	t.Run("clean env passes", func(t *testing.T) {
		v := AuditEnvBudget([]string{"JAVA_HOME=C:\\jdk", "USERNAME=alice", "X=1"}, lim)
		if !v.OK {
			t.Fatalf("expected ok, got %s", v.Reason)
		}
		if len(v.Entries) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(v.Entries))
		}
	})

	t.Run("path override blocked", func(t *testing.T) {
		for _, key := range []string{"PATH", "LD_PRELOAD", "JAVA_TOOL_OPTIONS", "DYLD_INSERT_LIBRARIES"} {
			v := AuditEnvBudget([]string{key + "=x"}, lim)
			if v.OK || v.Reason != "blocked-key:"+key {
				t.Fatalf("key %s: expected blocked-key, got ok=%v reason=%s", key, v.OK, v.Reason)
			}
		}
	})

	t.Run("nul byte value rejected", func(t *testing.T) {
		v := AuditEnvBudget([]string{"A=a\x00b"}, lim)
		if v.OK || v.Reason != "bad-value" {
			t.Fatalf("expected bad-value, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("control char value rejected", func(t *testing.T) {
		v := AuditEnvBudget([]string{"A=a\r\nX=y"}, lim)
		if v.OK || v.Reason != "bad-value" {
			t.Fatalf("expected bad-value, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("bad key rejected", func(t *testing.T) {
		for _, k := range []string{"1X=y", "A-B=y", "A B=y"} {
			v := AuditEnvBudget([]string{k}, lim)
			if v.OK || v.Reason != "bad-key" {
				t.Fatalf("key %q: expected bad-key, got ok=%v reason=%s", k, v.OK, v.Reason)
			}
		}
	})

	t.Run("entry without equals rejected", func(t *testing.T) {
		v := AuditEnvBudget([]string{"JUSTANAME"}, lim)
		if v.OK || v.Reason != "bad-entry" {
			t.Fatalf("expected bad-entry, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("too many entries rejected", func(t *testing.T) {
		small := EnvLimits{MaxEntries: 2, MaxTotalKB: 16, MaxKeyLen: 128, MaxValueLen: 4096}
		v := AuditEnvBudget([]string{"A=1", "B=2", "C=3"}, small)
		if v.OK || v.Reason != "too-many-entries" {
			t.Fatalf("expected too-many-entries, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("total size budget enforced", func(t *testing.T) {
		small := EnvLimits{MaxEntries: 128, MaxTotalKB: 1, MaxKeyLen: 128, MaxValueLen: 4096}
		big := make([]string, 40)
		for i := range big {
			big[i] = "KEY" + itoaSafe(i) + "=" + strings.Repeat("x", 100)
		}
		v := AuditEnvBudget(big, small)
		if v.OK || v.Reason != "too-large-env" {
			t.Fatalf("expected too-large-env, got ok=%v reason=%s", v.OK, v.Reason)
		}
	})

	t.Run("empty env passes", func(t *testing.T) {
		v := AuditEnvBudget(nil, lim)
		if !v.OK || len(v.Entries) != 0 {
			t.Fatalf("expected ok empty, got ok=%v entries=%d", v.OK, len(v.Entries))
		}
	})

	t.Run("defaults applied when zero", func(t *testing.T) {
		v := AuditEnvBudget([]string{"A=1"}, EnvLimits{})
		if !v.OK {
			t.Fatalf("expected defaults to apply, got %s", v.Reason)
		}
	})
}

func TestSummarizeEnvVerdict(t *testing.T) {
	lim := defaultEnvLimits()
	v := AuditEnvBudget([]string{"A=1", "B=2"}, lim)
	s := SummarizeEnvVerdict(v)
	if !strings.Contains(s, "ok") || !strings.Contains(s, "entries=2") {
		t.Fatalf("unexpected summary: %s", s)
	}
	v2 := AuditEnvBudget([]string{"LD_PRELOAD=x"}, lim)
	s2 := SummarizeEnvVerdict(v2)
	if !strings.Contains(s2, "blocked:blocked-key:LD_PRELOAD") || !strings.Contains(s2, "blocked=LD_PRELOAD") {
		t.Fatalf("unexpected blocked summary: %s", s2)
	}
}

func TestEnvKeyHelpers(t *testing.T) {
	lim := defaultEnvLimits()
	if !envKeyOK("JAVA_HOME", lim) || envKeyOK("HOME_DIR_1", lim) == false {
		t.Fatal("expected valid keys")
	}
	if envKeyOK("1ABC", lim) || envKeyOK("A-B", lim) || envKeyOK("", lim) {
		t.Fatal("expected invalid keys rejected")
	}
	if !envValueOK("normal value", lim) || envValueOK("bad\x00", lim) || envValueOK("bad\x1f", lim) {
		t.Fatal("value validation mismatch")
	}
	if !envKeyBlocked("Path") || !envKeyBlocked("LD_PRELOAD") || envKeyBlocked("SAFE_KEY") {
		t.Fatal("blocked key detection mismatch")
	}
}
