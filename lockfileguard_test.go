package main

import "testing"

func TestLFAcquireRelease(t *testing.T) {
	m := NewLFManager()
	if ok, _ := m.Acquire("instance-a", "t1", 10, 100); !ok {
		t.Fatal("first acquire should succeed")
	}
	if !m.Held("instance-a", 20) {
		t.Fatal("lock should be held")
	}
	if ok, _ := m.Release("instance-a", "t1"); !ok {
		t.Fatal("owner release should succeed")
	}
	if m.Held("instance-a", 20) {
		t.Fatal("lock should be released")
	}
}

func TestLFDoubleAcquire(t *testing.T) {
	m := NewLFManager()
	m.Acquire("r", "t1", 10, 100)
	ok, fs := m.Acquire("r", "t2", 20, 100)
	if ok || !LFHasReason(fs, LFReasonDoubleAcquire) {
		t.Fatalf("second owner must be blocked: ok=%v %v", ok, fs)
	}
}

func TestLFReacquireSameTokenLeak(t *testing.T) {
	m := NewLFManager()
	m.Acquire("r", "t1", 10, 100)
	ok, fs := m.Acquire("r", "t1", 20, 100)
	if ok || !LFHasReason(fs, LFReasonReacquireLeak) {
		t.Fatalf("re-acquire without release indicates leak: ok=%v %v", ok, fs)
	}
}

func TestLFReleaseWithoutAcquire(t *testing.T) {
	m := NewLFManager()
	ok, fs := m.Release("r", "t1")
	if ok || !LFHasReason(fs, LFReasonReleaseNotHeld) {
		t.Fatalf("release without acquire must fail: ok=%v %v", ok, fs)
	}
}

func TestLFReleaseByNonOwner(t *testing.T) {
	m := NewLFManager()
	m.Acquire("r", "t1", 10, 100)
	ok, fs := m.Release("r", "t2")
	if ok || !LFHasReason(fs, LFReasonReleaseWrongOwner) {
		t.Fatalf("non-owner release must fail: ok=%v %v", ok, fs)
	}
}

func TestLFStaleTakeover(t *testing.T) {
	m := NewLFManager()
	m.Acquire("r", "dead", 10, 5)
	// TTL 已过，新持有者接管；旧锁应被判陈旧
	if m.Held("r", 100) {
		t.Fatal("lock should be stale at tick 100")
	}
	ok, fs := m.Acquire("r", "alive", 100, 5)
	if !ok {
		t.Fatalf("stale lock should be takeable: %v", fs)
	}
	if !LFHasReason(fs, LFReasonStaleLock) {
		t.Fatalf("want stale warning on takeover: %v", fs)
	}
	if !m.Held("r", 101) {
		t.Fatal("new owner should hold lock")
	}
}

func TestLFHeartbeatRenews(t *testing.T) {
	m := NewLFManager()
	m.Acquire("r", "t1", 10, 5)
	m.Heartbeat("r", "t1", 13)
	// 若无心跳 16 即过期；续租后 16 仍持有
	if !m.Held("r", 16) {
		t.Fatal("heartbeat should extend ttl")
	}
}

func TestLFHeartbeatNonOwner(t *testing.T) {
	m := NewLFManager()
	m.Acquire("r", "t1", 10, 100)
	ok, fs := m.Heartbeat("r", "intruder", 20)
	if ok || !LFHasReason(fs, LFReasonReleaseNotHeld) {
		t.Fatalf("non-owner heartbeat must fail: ok=%v %v", ok, fs)
	}
}

func TestLFHeartbeatBackwards(t *testing.T) {
	m := NewLFManager()
	m.Acquire("r", "t1", 100, 100)
	ok, fs := m.Heartbeat("r", "t1", 50)
	if ok || !LFHasReason(fs, LFReasonFutureTimestamp) {
		t.Fatalf("backwards heartbeat (clock skew) must fail: ok=%v %v", ok, fs)
	}
}
