package main

import (
	"testing"
	"time"
)

func TestOnetimeToken_IssueConsume(t *testing.T) {
	s := NewOnetimeLaunchTokenStore(time.Minute)
	tok, err := s.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 16 {
		t.Fatalf("token too short: %s", tok)
	}
	if !s.Consume(tok) {
		t.Fatal("first consume must succeed")
	}
	if s.Consume(tok) {
		t.Fatal("second consume must fail (one-time)")
	}
}

func TestOnetimeToken_RejectEmpty(t *testing.T) {
	s := NewOnetimeLaunchTokenStore(time.Minute)
	if s.Consume("") {
		t.Fatal("empty token must be rejected")
	}
}

func TestOnetimeToken_RejectUnknown(t *testing.T) {
	s := NewOnetimeLaunchTokenStore(time.Minute)
	if s.Consume("deadbeef") {
		t.Fatal("unknown token must be rejected")
	}
}

func TestOnetimeToken_TTL(t *testing.T) {
	s := NewOnetimeLaunchTokenStore(50 * time.Millisecond)
	tok, _ := s.Issue()
	time.Sleep(120 * time.Millisecond)
	if s.Consume(tok) {
		t.Fatal("expired token must be rejected")
	}
	if s.Len() != 0 {
		t.Fatalf("expired token should be GC'd, len=%d", s.Len())
	}
}
