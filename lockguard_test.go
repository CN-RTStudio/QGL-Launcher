package main

import (
	"testing"
	"time"
)

// memLockStore 内存版 lockStore，测试注入用。
type memLockStore struct {
	payload []byte
}

func (m *memLockStore) Load() ([]byte, error) {
	if m == nil || m.payload == nil {
		return nil, nil
	}
	return m.payload, nil
}

func (m *memLockStore) Save(payload []byte) error {
	m.payload = payload
	return nil
}

func TestSetAndVerifyLaunchPIN(t *testing.T) {
	lim := defaultLockLimits()
	st := &memLockStore{}
	if err := SetLaunchPIN(st, "1234", "", lim); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	ok, reason, rem := VerifyLaunchPIN(st, "1234", lim)
	if !ok {
		t.Fatalf("correct pin rejected: %s", reason)
	}
	if rem != lim.MaxAttempt {
		t.Fatalf("remaining after success = %d want %d", rem, lim.MaxAttempt)
	}
	ok, _, _ = VerifyLaunchPIN(st, "9999", lim)
	if ok {
		t.Fatalf("wrong pin accepted")
	}
}

func TestLockPINWrongPinLimits(t *testing.T) {
	lim := defaultLockLimits()
	st := &memLockStore{}
	_ = SetLaunchPIN(st, "abcd", "", lim)
	for i := 0; i < lim.MaxAttempt; i++ {
		ok, _, _ := VerifyLaunchPIN(st, "nope", lim)
		if ok {
			t.Fatalf("wrong pin accepted at %d", i)
		}
	}
	// 达到上限后进入冷却
	ok, reason, rem := VerifyLaunchPIN(st, "abcd", lim)
	if ok {
		t.Fatalf("accepted during cooldown")
	}
	if reason != "pin-locked" {
		t.Fatalf("reason = %q want pin-locked", reason)
	}
	if rem != 0 {
		t.Fatalf("remaining during cooldown = %d want 0", rem)
	}
}

func TestLockPINCooldownExpiry(t *testing.T) {
	lim := defaultLockLimits()
	lim.Cooldown = 20 * time.Millisecond
	st := &memLockStore{}
	_ = SetLaunchPIN(st, "1234", "", lim)
	for i := 0; i < lim.MaxAttempt; i++ {
		_, _, _ = VerifyLaunchPIN(st, "bad", lim)
	}
	time.Sleep(40 * time.Millisecond)
	ok, _, _ := VerifyLaunchPIN(st, "1234", lim)
	if !ok {
		t.Fatalf("correct pin rejected after cooldown")
	}
}

func TestSetLaunchPINRequiresPrev(t *testing.T) {
	lim := defaultLockLimits()
	st := &memLockStore{}
	_ = SetLaunchPIN(st, "1234", "", lim)
	if err := SetLaunchPIN(st, "5678", "wrong-hmac", lim); err == nil {
		t.Fatalf("replacement with wrong prev accepted")
	}
	// 用正确 prev（当前 HMAC 摘要）换锁
	raw, _ := st.Load()
	cur := normalizeLockState(raw)
	if err := SetLaunchPIN(st, "5678", cur.HMACHex, lim); err != nil {
		t.Fatalf("replacement with correct prev failed: %v", err)
	}
	ok, _, _ := VerifyLaunchPIN(st, "5678", lim)
	if !ok {
		t.Fatalf("new pin rejected after rotation")
	}
}

func TestClearLaunchPIN(t *testing.T) {
	lim := defaultLockLimits()
	st := &memLockStore{}
	_ = SetLaunchPIN(st, "1234", "", lim)
	if err := ClearLaunchPIN(st, "9999", lim); err == nil {
		t.Fatalf("clear with wrong pin accepted")
	}
	if err := ClearLaunchPIN(st, "1234", lim); err != nil {
		t.Fatalf("clear failed: %v", err)
	}
	ok, reason, _ := VerifyLaunchPIN(st, "1234", lim)
	if ok || reason != "pin-unset" {
		t.Fatalf("verify after clear: ok=%v reason=%q", ok, reason)
	}
}

func TestLockStatus(t *testing.T) {
	lim := defaultLockLimits()
	st := &memLockStore{}
	configured, remaining, locked, _ := LockStatus(st, lim)
	if configured || locked || remaining != lim.MaxAttempt {
		t.Fatalf("unset status wrong: configured=%v remaining=%d locked=%v", configured, remaining, locked)
	}
	_ = SetLaunchPIN(st, "1234", "", lim)
	configured, remaining, locked, _ = LockStatus(st, lim)
	if !configured || locked || remaining != lim.MaxAttempt {
		t.Fatalf("armed status wrong: configured=%v remaining=%d locked=%v", configured, remaining, locked)
	}
}

func TestLockPINNoPlaintext(t *testing.T) {
	lim := defaultLockLimits()
	st := &memLockStore{}
	_ = SetLaunchPIN(st, "1234", "", lim)
	raw, _ := st.Load()
	for _, needle := range []string{"1234", "123"} {
		if containsBytes(raw, []byte(needle)) {
			t.Fatalf("plaintext pin leaked into store: %s", needle)
		}
	}
}

func containsBytes(hay, needle []byte) bool {
	if len(needle) == 0 || len(hay) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

func TestLockPINCorruptState(t *testing.T) {
	lim := defaultLockLimits()
	st := &memLockStore{payload: []byte(`{"hmac":"zz","salt":"00"}`)}
	ok, reason, _ := VerifyLaunchPIN(st, "1234", lim)
	if ok || reason != "pin-corrupt" {
		t.Fatalf("corrupt state: ok=%v reason=%q", ok, reason)
	}
	st.payload = []byte(`not-json`)
	ok, reason, _ = VerifyLaunchPIN(st, "1234", lim)
	if ok || reason != "pin-unset" {
		t.Fatalf("bad payload: ok=%v reason=%q", ok, reason)
	}
}

func TestLockPINShortPin(t *testing.T) {
	lim := defaultLockLimits()
	st := &memLockStore{}
	if err := SetLaunchPIN(st, "12", "", lim); err == nil {
		t.Fatalf("short pin accepted")
	}
	ok, reason, _ := VerifyLaunchPIN(st, "12", lim)
	if ok || reason != "pin-length-out-of-range" {
		t.Fatalf("short verify: ok=%v reason=%q", ok, reason)
	}
}

func TestSummarizeLockStatus(t *testing.T) {
	if s := SummarizeLockStatus(false, 5, false); s != "launch-lock unset" {
		t.Fatalf("unset summary wrong: %q", s)
	}
	if s := SummarizeLockStatus(true, 0, true); s != "launch-lock locked" {
		t.Fatalf("locked summary wrong: %q", s)
	}
	if s := SummarizeLockStatus(true, 3, false); s != "launch-lock armed remaining=3" {
		t.Fatalf("armed summary wrong: %q", s)
	}
}
