package main

import (
	"errors"
	"testing"
	"time"
)

func TestModpackLock_AcquireRelease(t *testing.T) {
	l := NewModpackInstallLock(time.Minute)
	if err := l.Acquire("inst/A"); err != nil {
		t.Fatalf("first acquire must pass: %v", err)
	}
	if err := l.Acquire("inst/A"); !errors.Is(err, ErrModpackBusy) {
		t.Fatalf("second acquire must busy, got %v", err)
	}
	if err := l.Acquire("inst/B"); err != nil {
		t.Fatalf("other instance independent: %v", err)
	}
	if err := l.Release("inst/A"); err != nil {
		t.Fatalf("release A: %v", err)
	}
	if err := l.Acquire("inst/A"); err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
}

func TestModpackLock_ReleaseNotHeld(t *testing.T) {
	l := NewModpackInstallLock(time.Minute)
	if err := l.Release("inst/ghost"); !errors.Is(err, ErrModpackNotLocked) {
		t.Fatalf("release ghost must error, got %v", err)
	}
}

func TestModpackLock_TTLExpiry(t *testing.T) {
	l := NewModpackInstallLock(20 * time.Millisecond)
	if err := l.Acquire("inst/A"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if err := l.Acquire("inst/A"); err != nil {
		t.Fatalf("expired lock must be auto-released, got %v", err)
	}
}

func TestModpackLock_HeldDirs(t *testing.T) {
	l := NewModpackInstallLock(time.Minute)
	_ = l.Acquire("inst/A")
	_ = l.Acquire("inst/B")
	dirs := l.HeldDirs()
	if len(dirs) != 2 {
		t.Fatalf("expected 2 held, got %v", dirs)
	}
}
