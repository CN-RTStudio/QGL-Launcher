package main

import (
	"testing"
)

func TestSourceFromHost(t *testing.T) {
	if sourceFromHost("libraries.minecraft.net") != ChecksumMojang {
		t.Fatal("mojang host should classify mojang")
	}
	if sourceFromHost("api.modrinth.com") != ChecksumModrinth {
		t.Fatal("modrinth host")
	}
	if sourceFromHost("127.0.0.1") != ChecksumLocalUMFS {
		t.Fatal("local host")
	}
}

func TestChooseAlgo(t *testing.T) {
	if chooseChecksumAlgo(ChecksumMojang) != AlgoSHA1 {
		t.Fatal("mojang must stay sha1")
	}
	if chooseChecksumAlgo(ChecksumAuthlib) != AlgoSHA256 {
		t.Fatal("authlib must stay sha256")
	}
	if chooseChecksumAlgo(ChecksumModrinth) != AlgoSHA512 {
		t.Fatal("modrinth prefer sha512")
	}
	if chooseChecksumAlgo(ChecksumLocalUMFS) != AlgoLocal {
		t.Fatal("local uses umfs")
	}
	if chooseChecksumAlgo(ChecksumUnknown) != "" {
		t.Fatal("unknown must not pick an algo")
	}
}

func TestIsExternalAlgorithm(t *testing.T) {
	if !isExternalAlgorithm(AlgoSHA1) || !isExternalAlgorithm(AlgoSHA256) || !isExternalAlgorithm(AlgoSHA512) {
		t.Fatal("external algos must be marked external")
	}
	if isExternalAlgorithm(AlgoLocal) {
		t.Fatal("umfs is not external")
	}
}

func TestSourceFromHostRejectsLookalikeSuffixes(t *testing.T) {
	cases := []struct {
		host string
		want ChecksumSource
	}{
		{"mojang.com", ChecksumMojang},
		{"MOJANG.COM", ChecksumMojang},
		{"mojang.com.", ChecksumMojang},
		{"piston-data.mojang.com:443", ChecksumMojang},
		{"libraries.minecraft.net", ChecksumMojang},
		{"evilmojang.com", ChecksumUnknown},
		{"mojang.com.attacker.example", ChecksumUnknown},
		{"minecraft.net.attacker.example", ChecksumUnknown},
		{"modrinth.com", ChecksumModrinth},
		{"cdn.modrinth.com", ChecksumModrinth},
		{"modrinth.com.evil.example", ChecksumUnknown},
		{"authlib.mojang.com", ChecksumMojang},
		{"authlib.example", ChecksumUnknown},
		{"authlib.org", ChecksumAuthlib},
		{"127.0.0.1", ChecksumLocalUMFS},
		{"127.0.0.1:8080", ChecksumLocalUMFS},
		{"localhost", ChecksumLocalUMFS},
		{"::1", ChecksumLocalUMFS},
		{"[::1]", ChecksumLocalUMFS},
		{"[::1]:8443", ChecksumLocalUMFS},
		{"127.0.0.1.attacker.example", ChecksumUnknown},
		{"::1.attacker.example", ChecksumUnknown},
		{"", ChecksumLocalUMFS},
		{"   ", ChecksumLocalUMFS},
		{"mojang.com\tattacker", ChecksumUnknown},
		{"mojang.com evil", ChecksumUnknown},
		{"mojang.com/path", ChecksumUnknown},
		{"10.0.0.5", ChecksumUnknown},
		{"8.8.8.8", ChecksumUnknown},
	}
	for _, c := range cases {
		if got := sourceFromHost(c.host); got != c.want {
			t.Fatalf("sourceFromHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestSourceFromHostRejectsEmbeddedUserinfo(t *testing.T) {
	cases := []string{
		"mojang.com@attacker.example",
		"attacker.example@mojang.com",
		"mojang.com:443@attacker.example",
	}
	for _, host := range cases {
		if got := sourceFromHost(host); got != ChecksumUnknown {
			t.Fatalf("sourceFromHost(%q) = %v, want Unknown", host, got)
		}
	}
}

func TestChecksumHostOnlyStripsPortAndBrackets(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"CDN.Modrinth.com:443", "cdn.modrinth.com", true},
		{"[fe80::1]:443", "fe80::1", true},
		{"  mojang.com.  ", "mojang.com", true},
		{"", "", false},
		{"[fe80::1", "", false},
		{"a..b", "", false},
	}
	for _, c := range cases {
		got, ok := checksumHostOnly(c.in)
		if ok != c.ok || got != c.want {
			t.Fatalf("checksumHostOnly(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
