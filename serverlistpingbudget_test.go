package main

import (
	"testing"
	"time"
)

func TestPingBudget_ThrottlePerHost(t *testing.T) {
	b := NewServerPingBudget(8, time.Second)
	ok, rel := b.TryAcquire("mc.example.com")
	if !ok {
		t.Fatal("first acquire must pass")
	}
	ok2, _ := b.TryAcquire("mc.example.com")
	if ok2 {
		t.Fatal("second acquire same host must be throttled")
	}
	rel()
}

func TestPingBudget_MaxInFlight(t *testing.T) {
	b := NewServerPingBudget(2, 0)
	ok1, r1 := b.TryAcquire("a")
	ok2, r2 := b.TryAcquire("b")
	ok3, _ := b.TryAcquire("c")
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("max in flight must be 2, got %v/%v/%v", ok1, ok2, ok3)
	}
	r1()
	r2()
	if b.InFlight() != 0 {
		t.Fatalf("after release in flight=0, got %d", b.InFlight())
	}
}

func TestPingBudget_ReleaseIdempotent(t *testing.T) {
	b := NewServerPingBudget(2, 0)
	_, rel := b.TryAcquire("x")
	rel()
	rel()
	if b.InFlight() != 0 {
		t.Fatalf("double release must not go negative, got %d", b.InFlight())
	}
}

func TestPingBudget_DifferentHostsParallel(t *testing.T) {
	b := NewServerPingBudget(4, time.Hour)
	seen := 0
	for _, h := range []string{"a", "b", "c", "d"} {
		if ok, rel := b.TryAcquire(h); ok {
			seen++
			rel()
		}
	}
	if seen != 4 {
		t.Fatalf("expected 4 distinct hosts allowed, got %d", seen)
	}
}
