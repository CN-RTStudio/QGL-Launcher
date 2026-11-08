package main

import (
	"testing"
)

func TestQuickplay_Singleplayer(t *testing.T) {
	if err := ValidateQuickPlayArg("singleplayer", "My World"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuickPlayArg("singleplayer", "../etc"); err == nil {
		t.Fatal("traversal must fail")
	}
	if err := ValidateQuickPlayArg("singleplayer", "a/b"); err == nil {
		t.Fatal("slash must fail")
	}
}

func TestQuickplay_Multiplayer(t *testing.T) {
	if err := ValidateQuickPlayArg("multiplayer", "mc.example.com:25565"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuickPlayArg("multiplayer", "mc.example.com"); err != nil {
		t.Fatalf("bare host should default port: %v", err)
	}
	if err := ValidateQuickPlayArg("multiplayer", "mc.example.com:99999"); err == nil {
		t.Fatal("bad port must fail")
	}
}

func TestQuickplay_RealmsAndGarbage(t *testing.T) {
	if err := ValidateQuickPlayArg("realms", "12345"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuickPlayArg("realms", "12/34"); err == nil {
		t.Fatal("slashes in realms id must fail")
	}
	if err := ValidateQuickPlayArg("nonsense", "x"); err == nil {
		t.Fatal("unknown mode must fail")
	}
	if err := ValidateQuickPlayArg("multiplayer", ""); err == nil {
		t.Fatal("empty must fail")
	}
}

func TestAllowQuickplay(t *testing.T) {
	if !AllowQuickplay("multiplayer", "1.2.3.4:25565") {
		t.Fatal("should allow clean mp")
	}
	if AllowQuickplay("singleplayer", "..\\win") {
		t.Fatal("should block traversal")
	}
}

func TestQuickplay_MultiplayerRejectsArgumentInjection(t *testing.T) {
	cases := []string{
		"mc.example.com:25565 --demo",
		"mc.example.com --demo",
		"mc.example.com:25565 --quickPlaySingleplayer x",
		"mc.example.com\t25565",
		"mc.example.com\n25565",
		"mc.example.com\r25565",
		"mc.example.com:25565\"",
		"mc.example.com:25565'",
		"mc.example.com:25565`calc",
		"user:pass@mc.example.com:25565",
		"mc.example.com:25565@evil.example",
		"mc.example.com/x",
		"mc.example.com?x=1",
		"mc.example.com#frag",
		"mc.example.com\\x",
		"mc.example.com:25565:25565",
		"mc.example.com:-1",
		"mc.example.com:+25565",
		"mc.example.com:025565",
		"mc.example.com:0",
		".example.com:25565",
		"example.com.:25565",
		"-example.com:25565",
		"example-.com:25565",
		"exa mple.com:25565",
		"münchen.example:25565",
		"mc.example.com :80",
	}
	for _, arg := range cases {
		if err := ValidateQuickPlayArg("multiplayer", arg); err == nil {
			t.Fatalf("multiplayer arg %q must be rejected", arg)
		}
	}
}

func TestQuickplay_MultiplayerAcceptsCleanForms(t *testing.T) {
	cases := []string{
		"mc.example.com",
		"mc.example.com:25565",
		"MC.EXAMPLE.COM:25565",
		"1.2.3.4:25565",
		"1.2.3.4",
		"[::1]:25565",
		"[2001:db8::1]:25565",
		"2001:db8::1",
		"xn--mnchen-3ha.example:25565",
		"a_b.example.com:25565",
	}
	for _, arg := range cases {
		if err := ValidateQuickPlayArg("multiplayer", arg); err != nil {
			t.Fatalf("multiplayer arg %q should pass, got %v", arg, err)
		}
	}
}

func TestQuickplay_RealmsIDCharset(t *testing.T) {
	good := []string{"12345", "abc-DEF_9", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for _, id := range good {
		if err := ValidateQuickPlayArg("realms", id); err != nil {
			t.Fatalf("realms id %q should pass, got %v", id, err)
		}
	}
	bad := []string{
		"12 34",
		"12\t34",
		"12/34",
		"12\\34",
		"12?x",
		"12&x",
		"12#x",
		"12%20",
		"12@x",
		"--demo",
		"",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for _, id := range bad {
		if err := ValidateQuickPlayArg("realms", id); err == nil {
			t.Fatalf("realms id %q must be rejected", id)
		}
	}
}

func TestQuickplay_Helpers(t *testing.T) {
	for _, p := range []string{"1", "25565", "65535"} {
		if !isSafeQuickPlayPort(p) {
			t.Fatalf("port %q should be safe", p)
		}
	}
	for _, p := range []string{"", "0", "65536", "99999", "-1", "+1", " 1", "1 ", "0x50", "1e3"} {
		if isSafeQuickPlayPort(p) {
			t.Fatalf("port %q must be rejected", p)
		}
	}
	for _, h := range []string{"localhost", "a.b", "1.2.3.4", "::1"} {
		if !isSafeQuickPlayHost(h) {
			t.Fatalf("host %q should be safe", h)
		}
	}
	for _, h := range []string{"", ".", ".a", "a.", "a..b", "-a", "a-", "a b", "a:b", "a/b", "[::1]", "%41"} {
		if isSafeQuickPlayHost(h) {
			t.Fatalf("host %q must be rejected", h)
		}
	}
	if !isSafeRealmsID("12-34_ab") {
		t.Fatal("clean realms id should be safe")
	}
	if isSafeRealmsID("12 34") || isSafeRealmsID("") {
		t.Fatal("dirty realms id must be rejected")
	}
}
