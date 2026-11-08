package main

import (
	"strings"
	"testing"
)

func TestIsAllowedManifestURL_MojangOK(t *testing.T) {
	if !IsAllowedManifestURL("https://piston-meta.mojang.com/mc/game/version_manifest.json") {
		t.Fatal("mojang meta must be allowed")
	}
}

func TestIsAllowedManifestURL_ForgeOK(t *testing.T) {
	if !IsAllowedManifestURL("https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json") {
		t.Fatal("forge host must be allowed")
	}
}

func TestIsAllowedManifestURL_FileSchemeRejected(t *testing.T) {
	if IsAllowedManifestURL("file:///etc/passwd") {
		t.Fatal("file:// must be rejected")
	}
}

func TestIsAllowedManifestURL_HTTPSOnly(t *testing.T) {
	if IsAllowedManifestURL("http://piston-meta.mojang.com/x") {
		t.Fatal("http must be rejected, only https allowed")
	}
}

func TestIsAllowedManifestURL_UnknownHostRejected(t *testing.T) {
	if IsAllowedManifestURL("https://evil.com/manifest.json") {
		t.Fatal("unknown host must be rejected")
	}
}

func TestNormalizeManifestURL_StripsFragment(t *testing.T) {
	out, ok := NormalizeManifestURL("https://piston-meta.mojang.com/x#frag")
	if !ok {
		t.Fatal("should normalize")
	}
	if strings.Contains(out, "#") {
		t.Fatalf("fragment must be stripped: %s", out)
	}
}
