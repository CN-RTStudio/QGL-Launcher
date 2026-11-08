package main

import (
	"testing"
)

func TestServerPack_AllowedHost(t *testing.T) {
	good := []string{
		"https://piston-data.minecraft.net/pack.zip",
		"https://resources.mojang.com/pack.zip",
		"https://minecraft.net/p.zip",
	}
	for _, g := range good {
		if err := ValidateServerPackURL(g, nil); err != nil {
			t.Fatalf("%s should pass: %v", g, err)
		}
	}
}

func TestServerPack_BadScheme(t *testing.T) {
	if err := ValidateServerPackURL("http://piston-data.minecraft.net/p.zip", nil); err == nil {
		t.Fatal("http must be rejected")
	}
}

func TestServerPack_UnknownHost(t *testing.T) {
	if err := ValidateServerPackURL("https://evil.example.com/p.zip", nil); err == nil {
		t.Fatal("unknown host must be rejected")
	}
}

func TestServerPack_ExtraAllowed(t *testing.T) {
	extra := []string{"modpacks.example.net"}
	if err := ValidateServerPackURL("https://modpacks.example.net/p.zip", extra); err != nil {
		t.Fatalf("extra-allowed host must pass: %v", err)
	}
}

func TestServerPack_Invalid(t *testing.T) {
	if err := ValidateServerPackURL("", nil); err == nil {
		t.Fatal("empty must fail")
	}
	if err := ValidateServerPackURL("://nope", nil); err == nil {
		t.Fatal("bad url must fail")
	}
}

func TestFilterServerPackList(t *testing.T) {
	in := []string{
		"https://piston-data.minecraft.net/a.zip",
		"https://evil.com/b.zip",
		"http://piston-data.minecraft.net/c.zip",
	}
	got := FilterServerPackList(in, nil)
	if len(got) != 1 {
		t.Fatalf("filtered = %v", got)
	}
}
