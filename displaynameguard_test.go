package main

import (
	"strings"
	"testing"
)

func TestInspectDisplayName_Clean(t *testing.T) {
	for _, n := range []string{"", "  ", "Vanilla SMP", "mc.example.com", "Мой Сервер"} {
		got := inspectDisplayName(n)
		for _, f := range got {
			if f == flagMixedScript || f == flagBidiOverride || f == flagZeroWidth {
				t.Fatalf("clean name %q unexpectedly flagged %v", n, f)
			}
		}
	}
}

func TestInspectDisplayName_BidiOverride(t *testing.T) {
	// "evil" + RLO + "moc.lebal" 在 UI 上会被翻转成 label.com 观感。
	got := inspectDisplayName("evil​\u202Eback")
	if !hasFlag(got, flagBidiOverride) {
		t.Fatalf("want bidi-override flag, got %v", got)
	}
}

func TestInspectDisplayName_ZeroWidth(t *testing.T) {
	got := inspectDisplayName("goo\u200Bgle")
	if !hasFlag(got, flagZeroWidth) {
		t.Fatalf("want zero-width flag, got %v", got)
	}
}

func TestInspectDisplayName_BidiMark(t *testing.T) {
	got := inspectDisplayName("a\u200Fb")
	if !hasFlag(got, flagBiDiMark) {
		t.Fatalf("want bidi-mark flag, got %v", got)
	}
}

func TestInspectDisplayName_MixedScriptHomograph(t *testing.T) {
	// Latin "g" + Cyrillic "оо" (U+043E) + "gle" -> g[Cyrillic oo]gle
	mixed := "g" + string(rune(0x043E)) + string(rune(0x043E)) + "gle"
	got := inspectDisplayName(mixed)
	if !hasFlag(got, flagMixedScript) {
		t.Fatalf("want mixed-script flag for %q, got %v", mixed, got)
	}
}

func TestInspectDisplayName_PureCyrillicNotFlagged(t *testing.T) {
	// 纯西里尔服务器名不应触发 mixed-script。
	got := inspectDisplayName("ПриветМир")
	if hasFlag(got, flagMixedScript) {
		t.Fatalf("pure Cyrillic name wrongly flagged mixed-script: %v", got)
	}
}

func TestInspectDisplayName_OrderAndDedup(t *testing.T) {
	mixed := "a\u200B\u200B" // 两个 ZWSP，标签只应出现一次
	got := inspectDisplayName(mixed)
	count := 0
	for _, f := range got {
		if f == flagZeroWidth {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("zero-width flag should be deduped, got %v", got)
	}
}

func TestDisplayNameLooksSuspicious(t *testing.T) {
	if displayNameLooksSuspicious("plain name") {
		t.Fatal("plain name should not be suspicious")
	}
	if !displayNameLooksSuspicious("a\u202Eb") {
		t.Fatal("RLO name should be suspicious")
	}
}

func TestEscapeInvisibleForDisplay(t *testing.T) {
	out := escapeInvisibleForDisplay("a\u200Bb")
	if !strings.Contains(out, "[U+200B]") {
		t.Fatalf("zero-width should be replaced by tag, got %q", out)
	}
	if strings.ContainsRune(out, 0x200B) {
		t.Fatalf("zero-width rune should be gone, got %q", out)
	}
	if !strings.HasPrefix(out, "a") || !strings.HasSuffix(out, "b") {
		t.Fatalf("visible edge chars must be preserved, got %q", out)
	}
}

func hasFlag(list []displayNameFlag, f displayNameFlag) bool {
	for _, x := range list {
		if x == f {
			return true
		}
	}
	return false
}
