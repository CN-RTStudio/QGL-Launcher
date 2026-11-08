package main

import (
	"strings"
	"testing"
)

func TestModMetaGood(t *testing.T) {
	lim := defaultModMetaLimits()
	raw := `{"id":"my_mod","version":"1.0.0","name":"My Mod","description":"desc",
	  "authors":["a","b"],"depends":{"fabricloader":">=0.14"},"mixins":["my_mod.mixins.json"]}`
	vd := ValidateFabricModMeta([]byte(raw), lim)
	if !vd.OK {
		t.Fatalf("good rejected: %s", vd.Reason)
	}
	if vd.Doc.ID != "my_mod" {
		t.Fatalf("id=%q", vd.Doc.ID)
	}
}

func TestModMetaBad(t *testing.T) {
	lim := defaultModMetaLimits()
	bad := []struct {
		name string
		raw  string
		want string
	}{
		{"id-upper", `{"id":"MyMod"}`, "id-illegal"},
		{"id-empty", `{"id":""}`, "id-illegal"},
		{"id-ctrl", `{"id":"a\x01b"}`, "id-illegal"},
		{"parse", `{"id":`, "parse-fail"},
		{"dep-id", `{"id":"a","depends":{"UPPER":"1"}}`, "dep-id-illegal:"},
		{"mixin-dotdot", `{"id":"a","mixins":["../x.json"]}`, "mixin:dotdot"},
		{"mixin-abs", `{"id":"a","mixins":["/x.json"]}`, "mixin:absolute"},
	}
	for _, c := range bad {
		vd := ValidateFabricModMeta([]byte(c.raw), lim)
		if vd.OK || !strings.Contains(vd.Reason, c.want) {
			t.Fatalf("%s: ok=%v reason=%q want %q", c.name, vd.OK, vd.Reason, c.want)
		}
	}
}

func TestModMetaOverflow(t *testing.T) {
	lim := defaultModMetaLimits()
	lim.MaxDeps = 2
	raw := `{"id":"a","depends":{"x":"1","y":"1","z":"1"}}`
	vd := ValidateFabricModMeta([]byte(raw), lim)
	if vd.OK || vd.Reason != "deps-overflow" {
		t.Fatalf("deps overflow: %v", vd)
	}
	lim = defaultModMetaLimits()
	lim.MaxMixins = 1
	raw = `{"id":"a","mixins":["a.json","b.json"]}`
	vd = ValidateFabricModMeta([]byte(raw), lim)
	if vd.OK || vd.Reason != "mixins-overflow" {
		t.Fatalf("mixins overflow: %v", vd)
	}
}

func TestModFieldSan(t *testing.T) {
	lim := defaultModMetaLimits()
	if s := modFieldSan("a\x01b\x02c", lim); s != "abc" {
		t.Fatalf("strip wrong: %q", s)
	}
	if s := modFieldSan(strings.Repeat("x", 5000), lim); len(s) > lim.MaxFieldRunes {
		t.Fatalf("truncate wrong: len=%d", len(s))
	}
}

func TestSummarizeModMetaVerdict(t *testing.T) {
	if s := SummarizeModMetaVerdict(modMetaVerdict{OK: true, Doc: fabricModDoc{ID: "a"}}); s != "modmeta ok id=a deps=0" {
		t.Fatalf("summary wrong: %q", s)
	}
	if s := SummarizeModMetaVerdict(modMetaVerdict{OK: false, Reason: "id-illegal"}); s != "modmeta bad id-illegal" {
		t.Fatalf("summary wrong: %q", s)
	}
}
