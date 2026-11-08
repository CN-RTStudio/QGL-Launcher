package main

import "testing"

func TestH2NormalTraffic(t *testing.T) {
	m := NewH2Monitor(DefaultH2Policy())
	// 打开 20 个流，仅取消其中 4 个（20%），属正常取消比例
	for i := 0; i < 20; i++ {
		if ok, _ := m.OnOpen(i); !ok {
			t.Fatal("open should be allowed")
		}
	}
	for i := 0; i < 4; i++ {
		if ok, _ := m.OnReset(i); !ok {
			t.Fatalf("normal reset should be allowed: %s", m.BlockedReason())
		}
	}
	if m.Blocked() {
		t.Fatalf("normal traffic must not block: %s", m.BlockedReason())
	}
}

func TestH2ConcurrentLimit(t *testing.T) {
	m := NewH2Monitor(H2Policy{MaxConcurrentStreams: 4, MaxResetPerWindow: 1000,
		ResetRatioPercent: 100, MaxGOAWAYReconnects: 3, WindowTicks: 10})
	for i := 0; i < 4; i++ {
		m.OnOpen(i)
	}
	if ok, fs := m.OnOpen(99); ok || len(fs) == 0 {
		t.Fatalf("want concurrent stream limit, ok=%v fs=%v", ok, fs)
	}
}

func TestH2RapidResetBurst(t *testing.T) {
	// 放宽并发与比例阈值，隔离出"窗口内 reset 数"这一条判定
	pol := H2Policy{MaxConcurrentStreams: 1000, MaxResetPerWindow: 100,
		ResetRatioPercent: 100, MaxGOAWAYReconnects: 3, WindowTicks: 100}
	m := NewH2Monitor(pol)
	n := pol.MaxResetPerWindow + 5
	for i := 0; i < n; i++ {
		m.OnOpen(i)
	}
	blocked := false
	for i := 0; i < n; i++ {
		if ok, _ := m.OnReset(i); !ok {
			blocked = true
			break
		}
	}
	if !blocked || m.BlockedReason() != H2ReasonResetBurst {
		t.Fatalf("want rapid reset burst, blocked=%v reason=%s", blocked, m.BlockedReason())
	}
}

func TestH2HighResetRatio(t *testing.T) {
	m := NewH2Monitor(H2Policy{MaxConcurrentStreams: 1000, MaxResetPerWindow: 100000,
		ResetRatioPercent: 80, MaxGOAWAYReconnects: 3, WindowTicks: 10})
	// 10 开 9 取消（90% > 80%，且 opened>=10）
	for i := 0; i < 10; i++ {
		m.OnOpen(i)
	}
	fired := false
	for i := 0; i < 9; i++ {
		if ok, _ := m.OnReset(i); !ok {
			fired = true
			break
		}
	}
	if !fired || m.BlockedReason() != H2ReasonResetRatio {
		t.Fatalf("want high reset ratio, fired=%v reason=%s", fired, m.BlockedReason())
	}
}

func TestH2UnknownStreamReset(t *testing.T) {
	m := NewH2Monitor(DefaultH2Policy())
	if ok, fs := m.OnReset(12345); ok || len(fs) == 0 {
		t.Fatalf("want unknown stream reset, ok=%v fs=%v", ok, fs)
	}
}

func TestH2DuplicateOpen(t *testing.T) {
	m := NewH2Monitor(DefaultH2Policy())
	m.OnOpen(2)
	if ok, _ := m.OnOpen(2); ok {
		t.Fatal("duplicate stream open should be rejected")
	}
}

func TestH2GOAWAYReconnectStorm(t *testing.T) {
	m := NewH2Monitor(DefaultH2Policy())
	m.OnGOAWAY()
	allowed := 0
	for i := 0; i < 10; i++ {
		if ok, _ := m.OnReconnect(); ok {
			allowed++
		}
	}
	// 允许 MaxGOAWAYReconnects(3) 次，第 4 次起拒绝
	if allowed != DefaultH2Policy().MaxGOAWAYReconnects {
		t.Fatalf("want %d allowed reconnects, got %d",
			DefaultH2Policy().MaxGOAWAYReconnects, allowed)
	}
	if m.BlockedReason() != H2ReasonGOAWAYReconnect {
		t.Fatalf("want goaway reconnect block, got %s", m.BlockedReason())
	}
}

func TestH2ReconnectWithoutGOAWAY(t *testing.T) {
	m := NewH2Monitor(DefaultH2Policy())
	for i := 0; i < 20; i++ {
		if ok, _ := m.OnReconnect(); !ok {
			t.Fatal("reconnect without GOAWAY should always be allowed")
		}
	}
}

func TestH2WindowRollsOff(t *testing.T) {
	m := NewH2Monitor(H2Policy{MaxConcurrentStreams: 1000, MaxResetPerWindow: 5,
		ResetRatioPercent: 100, MaxGOAWAYReconnects: 3, WindowTicks: 4})
	// 在窗口内取消 4 个（<=5），随后推进足够 tick 让旧记录滑出，再取消不应触发 burst
	for i := 0; i < 4; i++ {
		m.OnOpen(i)
		m.OnReset(i)
	}
	for t := 0; t < 5; t++ {
		m.AdvanceTick()
	}
	if m.Blocked() {
		t.Fatalf("old resets should have rolled off: %s", m.BlockedReason())
	}
}

func TestH2SetMaxConcurrent(t *testing.T) {
	m := NewH2Monitor(DefaultH2Policy())
	m.SetMaxConcurrent(2)
	m.OnOpen(0)
	m.OnOpen(2)
	if ok, _ := m.OnOpen(4); ok {
		t.Fatal("updated max concurrent should be enforced")
	}
}

func TestH2ActiveCount(t *testing.T) {
	m := NewH2Monitor(DefaultH2Policy())
	m.OnOpen(1)
	m.OnOpen(3)
	if m.ActiveCount() != 2 {
		t.Fatalf("active count wrong %d", m.ActiveCount())
	}
	m.OnReset(1)
	if m.ActiveCount() != 1 {
		t.Fatalf("active count after reset wrong %d", m.ActiveCount())
	}
}
