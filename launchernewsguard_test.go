package main

import (
	"testing"
)

func TestNewsFeed_Good(t *testing.T) {
	good := []string{
		"https://launcher.mojang.com/news.json",
		"https://www.minecraft.net/news.json",
	}
	for _, g := range good {
		if err := ValidateNewsFeedURL(g, nil); err != nil {
			t.Fatalf("%s should pass: %v", g, err)
		}
	}
}

func TestNewsFeed_BadScheme(t *testing.T) {
	if err := ValidateNewsFeedURL("http://launcher.mojang.com/news.json", nil); err == nil {
		t.Fatal("http must be rejected")
	}
}

func TestNewsFeed_UnknownHost(t *testing.T) {
	if err := ValidateNewsFeedURL("https://evil.example/news.json", nil); err == nil {
		t.Fatal("unknown host must be rejected")
	}
}

func TestNewsFeed_ExtraAllowed(t *testing.T) {
	extra := []string{"news.myserver.net"}
	if err := ValidateNewsFeedURL("https://news.myserver.net/n.json", extra); err != nil {
		t.Fatalf("extra allowed host should pass: %v", err)
	}
}

func TestNewsFeed_Invalid(t *testing.T) {
	if err := ValidateNewsFeedURL("", nil); err == nil {
		t.Fatal("empty must fail")
	}
	if err := ValidateNewsFeedURL("://nope", nil); err == nil {
		t.Fatal("bad url must fail")
	}
}
