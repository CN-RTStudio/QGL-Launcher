package main

import (
	"strings"
	"testing"
)

func TestExtraEnvNameProblem(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want envProblem
	}{
		{"plain ok", "JAVA_HOME", envProblemNone},
		{"lowercase ok", "path", envProblemNone},
		{"underscore digits ok", "APP_DATA_2", envProblemNone},
		{"empty", "", envProblemEmptyName},
		{"leading space", " PATH", envProblemNamePadding},
		{"trailing tab", "PATH\t", envProblemNamePadding},
		{"only spaces", "   ", envProblemNamePadding},
		{"equals inside", "A=B", envProblemNameEquals},
		{"nul inside", "A\x00B", envProblemNameNUL},
		{"tab inside", "A\tB", envProblemNameControl},
		{"newline inside", "A\nB", envProblemNameControl},
		{"del inside", "A\x7fB", envProblemNameControl},
		{"high byte not control", "A\x80B", envProblemNone},
		{"too long", strings.Repeat("A", envNameMaxBytes+1), envProblemNameTooLong},
		{"at limit ok", strings.Repeat("A", envNameMaxBytes), envProblemNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extraEnvNameProblem(c.in); got != c.want {
				t.Fatalf("extraEnvNameProblem(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestExtraEnvValueProblem(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want envProblem
	}{
		{"plain ok", "C:\\jdk", envProblemNone},
		{"empty ok", "", envProblemNone},
		{"unicode ok", "配置", envProblemNone},
		{"esc rejected in extra", "x\x1by", envProblemValueControl},
		{"nul rejected", "x\x00JAVA_TOOL_OPTIONS=-javaagent:a", envProblemValueNUL},
		{"tab rejected", "a\tb", envProblemValueControl},
		{"del rejected", "a\x7fb", envProblemValueControl},
		{"too long", strings.Repeat("v", envValueMaxBytes+1), envProblemValueTooLong},
		{"at limit ok", strings.Repeat("v", envValueMaxBytes), envProblemNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extraEnvValueProblem(c.in); got != c.want {
				t.Fatalf("extraEnvValueProblem(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestInheritedEnvProblemIsLoose(t *testing.T) {
	// 继承环境只拦 NUL / 空键，ESC 等控制字符必须放行（LS_COLORS 合法使用 ESC）。
	if got := inheritedEnvProblem("LS_COLORS", "di=1;34\x1b:ex=1;32"); got != envProblemNone {
		t.Fatalf("ESC in inherited value should be allowed, got %q", got)
	}
	if got := inheritedEnvProblem("OK", "a\x00b"); got != envProblemValueNUL {
		t.Fatalf("NUL in inherited value must reject, got %q", got)
	}
	if got := inheritedEnvProblem("A\x00B", "v"); got != envProblemNameNUL {
		t.Fatalf("NUL in inherited name must reject, got %q", got)
	}
	if got := inheritedEnvProblem("", "v"); got != envProblemEmptyName {
		t.Fatalf("empty inherited name must reject, got %q", got)
	}
}

func TestAcceptExtraEnv(t *testing.T) {
	extra := map[string]string{
		"JAVA_HOME": "C:\\jdk",
		" APPDATA":  "blocked-padding",
		"BAD=NAME":  "blocked-equals",
		"CTL":       "a\tb",
		"NULVAL":    "x\x00JAVA_TOOL_OPTIONS=-javaagent:evil",
		"EMPTY":     "",
		"GOOD2":     "ok",
		"NAME\tBAD": "v",
	}

	accepted, rejected := acceptExtraEnv(extra)

	if len(accepted) != 3 {
		t.Fatalf("accepted len = %d, want 3: %v", len(accepted), accepted)
	}
	for _, k := range []string{"JAVA_HOME", "EMPTY", "GOOD2"} {
		if _, ok := accepted[k]; !ok {
			t.Fatalf("expected %q accepted, map=%v", k, accepted)
		}
	}
	if len(rejected) != 5 {
		t.Fatalf("rejected len = %d, want 5: %+v", len(rejected), rejected)
	}
	// 被拒列表必须稳定有序：先按名字再按原因。
	for i := 1; i < len(rejected); i++ {
		a := rejected[i-1]
		b := rejected[i]
		if a.Name > b.Name || (a.Name == b.Name && a.Reason > b.Reason) {
			t.Fatalf("rejected not sorted at %d: %+v !<= %+v", i, a, b)
		}
	}
	// 任意一条被拒原因都必须是非空的已知问题码。
	for _, r := range rejected {
		if r.Reason == envProblemNone {
			t.Fatalf("rejected entry with no reason: %+v", r)
		}
	}
}

func TestSanitizeInheritedEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"SystemRoot=C:\\Windows",
		"GOOD=yes",
		"BADNUL=x\x00y",
		"=C:=C:\\drive-cwd", // drive-cwd 变量键为空：对 JVM 子进程一律丢弃
		"NOEQUALSPLIT",      // 缺 '='，丢弃
	}
	kept, dropped := sanitizeInheritedEnv(in)
	if len(kept) != 3 {
		t.Fatalf("kept len = %d, want 3: %q", len(kept), kept)
	}
	if len(dropped) != 3 {
		t.Fatalf("dropped len = %d, want 3: %+v", len(dropped), dropped)
	}
	wantKept := map[string]bool{"PATH=/usr/bin": false, "SystemRoot=C:\\Windows": false, "GOOD=yes": false}
	for _, e := range kept {
		if _, ok := wantKept[e]; ok {
			wantKept[e] = true
		} else {
			t.Fatalf("unexpected kept entry %q", e)
		}
	}
	for k, found := range wantKept {
		if !found {
			t.Fatalf("expected to keep %q", k)
		}
	}
	for _, d := range dropped {
		if d.Reason == envProblemNone {
			t.Fatalf("dropped entry needs a reason: %+v", d)
		}
	}
}

func TestEnvBlockByteSizeAndLimit(t *testing.T) {
	if got := envBlockByteSize(nil); got != 1 {
		t.Fatalf("nil block size = %d, want 1 (terminator only)", got)
	}
	if got := envBlockByteSize([]string{}); got != 1 {
		t.Fatalf("empty block size = %d, want 1", got)
	}
	entries := []string{"A=1", "BB=22"}
	// len: 3 + 1 + 5 + 1 + 1 terminator = 11
	if got := envBlockByteSize(entries); got != 11 {
		t.Fatalf("block size = %d, want 11", got)
	}
	if !envBlockWithinLimit(entries, 11) {
		t.Fatalf("block of exactly limit bytes should fit")
	}
	if envBlockWithinLimit(entries, 10) {
		t.Fatalf("block over limit must not fit")
	}
	if envBlockWithinLimit(entries, 0) {
		t.Fatalf("limit 0 must reject everything")
	}
}

func TestEnvHasC0ControlByteSemantics(t *testing.T) {
	control := []string{"\x00", "\x01", "\x10", "\x1f", "\x7f", "a\rb"}
	for _, s := range control {
		if !envHasC0Control(s) {
			t.Fatalf("expected C0/DEL detected in %q", s)
		}
	}
	clean := []string{"", "abc", "\x80\xff", "中文", "\x20"}
	for _, s := range clean {
		if envHasC0Control(s) {
			t.Fatalf("did not expect C0/DEL for %q", s)
		}
	}
}
