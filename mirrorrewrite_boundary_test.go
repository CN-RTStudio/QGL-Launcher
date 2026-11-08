package main

import "testing"

func TestRewriteURIPrefixRequiresHostBoundary(t *testing.T) {
	const base = "https://bmclapi2.bangbang93.com"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"suffix-host attack is not rewritten",
			"https://piston-meta.mojang.com.evil.test/v1/x.json",
			"https://piston-meta.mojang.com.evil.test/v1/x.json"},
		{"suffix-host with port is not rewritten",
			"https://launcher.mojang.com.evil.test:443/v1/x.jar",
			"https://launcher.mojang.com.evil.test:443/v1/x.jar"},
		{"prefix embedded in query is not rewritten",
			"https://safe.test/go?u=https://piston-meta.mojang.com/v1/x.json",
			"https://safe.test/go?u=https://piston-meta.mojang.com/v1/x.json"},
		{"prefix embedded in path is not rewritten",
			"https://safe.test/https://launcher.mojang.com/v1/x.jar",
			"https://safe.test/https://launcher.mojang.com/v1/x.jar"},
		{"exact host root is rewritten",
			"https://piston-meta.mojang.com",
			base},
		{"slash boundary is rewritten",
			"https://piston-meta.mojang.com/v1/a.json",
			base + "/v1/a.json"},
		{"query boundary is rewritten",
			"https://piston-meta.mojang.com?x=1",
			base + "?x=1"},
		{"fragment boundary is rewritten",
			"https://piston-meta.mojang.com#frag",
			base + "#frag"},
		{"port boundary is rewritten",
			"https://piston-meta.mojang.com:8443/v1/a.json",
			base + ":8443/v1/a.json"},
		{"userinfo form is not rewritten",
			"https://user:pass@piston-meta.mojang.com/v1/a.json",
			"https://user:pass@piston-meta.mojang.com/v1/a.json"},
		{"uppercase scheme is not rewritten",
			"HTTPS://piston-meta.mojang.com/v1/a.json",
			"HTTPS://piston-meta.mojang.com/v1/a.json"},
		{"empty prefix rule is skipped",
			"https://example.test/a",
			"https://example.test/a"},
	}
	rules := []urlPrefixRule{
		{"https://piston-meta.mojang.com", base},
		{"https://launcher.mojang.com", base},
		{"", "https://bad"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rewriteURLPrefixes(c.in, rules); got != c.want {
				t.Fatalf("rewriteURLPrefixes(%q)=%q want %q", c.in, got, c.want)
			}
		})
	}
}

func TestMirrorPrefixEndsAtHostBoundary(t *testing.T) {
	cases := map[string]bool{
		"":      true,
		"/":     true,
		"/v1/a": true,
		"?q=1":  true,
		"#frag": true,
		":8443": true,
		".evil": false,
		"-evil": false,
		"_evil": false,
		"%2f":   false,
		"@evil": false,
	}
	for rest, want := range cases {
		if got := mirrorPrefixEndsAtHostBoundary(rest); got != want {
			t.Errorf("mirrorPrefixEndsAtHostBoundary(%q)=%v want %v", rest, got, want)
		}
	}
}

func TestRewriteLauncherURLStopsSuffixHost(t *testing.T) {
	in := "https://piston-meta.mojang.com.evil.test/v1/packages/x/y.json"
	if got := rewriteLauncherURLToBMCL(in); got != in {
		t.Fatalf("suffix host must not be rewritten, got %q", got)
	}
	if got := rewriteMetaIndexURLToBMCL(in); got != in {
		t.Fatalf("suffix host must not be rewritten by meta rules, got %q", got)
	}
	if got := rewriteMappedDataURLToBMCL(in); got != in {
		t.Fatalf("suffix host must not be rewritten by data rules, got %q", got)
	}
}
