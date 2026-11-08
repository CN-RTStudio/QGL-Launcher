package main

import "testing"

func TestGZBNormalCSS(t *testing.T) {
	mon := NewGZBMonitor(DefaultGZBPolicy(), 4000)
	// 压缩 4000 -> 12000（比 3），分 4 批
	for i := 0; i < 4; i++ {
		if safe, _ := mon.Observe(1000, 3000); !safe {
			t.Fatalf("normal css should be safe at batch %d (%s)", i, mon.AbortReason())
		}
	}
	if safe, _ := mon.Finalize(); !safe {
		t.Fatal("finalize should be clean for normal content")
	}
}

func TestGZBTotalExceeded(t *testing.T) {
	mon := NewGZBMonitor(DefaultGZBPolicy(), 0)
	// 每批 8MB 产出 / 8MB 入（ratio=1），多次累计超过 256MB
	for i := 0; i < 40; i++ {
		safe, _ := mon.Observe(8*1024*1024, 8*1024*1024)
		if !safe {
			if mon.AbortReason() != GZBReasonTotalExceeded {
				t.Fatalf("want total exceeded, got %s", mon.AbortReason())
			}
			return
		}
	}
	t.Fatal("expected total-exceeded abort")
}

func TestGZBBurstExceeded(t *testing.T) {
	mon := NewGZBMonitor(DefaultGZBPolicy(), 0)
	safe, _ := mon.Observe(1024, 32*1024*1024)
	if safe || mon.AbortReason() != GZBReasonBurstExceeded {
		t.Fatalf("want burst exceeded, safe=%v reason=%s", safe, mon.AbortReason())
	}
}

func TestGZBRatioExceeded(t *testing.T) {
	mon := NewGZBMonitor(DefaultGZBPolicy(), 1000)
	// 1000 压缩字节产出 300000（比 300 > 200）
	safe, _ := mon.Observe(1000, 300000)
	if safe || mon.AbortReason() != GZBReasonRatioExceeded {
		t.Fatalf("want ratio exceeded, safe=%v reason=%s", safe, mon.AbortReason())
	}
}

func TestGZBSustainedExpansion(t *testing.T) {
	mon := NewGZBMonitor(DefaultGZBPolicy(), 0)
	// 单批比 600（>=500），连续 4 批触发；总量与单批都不超
	for i := 0; i < 4; i++ {
		safe, _ := mon.Observe(100, 60000)
		if !safe {
			if mon.AbortReason() != GZBReasonSustainedExpansion {
				t.Fatalf("want sustained, got %s", mon.AbortReason())
			}
			return
		}
	}
	t.Fatal("expected sustained expansion abort")
}

func TestGZBSustainedRecovers(t *testing.T) {
	mon := NewGZBMonitor(DefaultGZBPolicy(), 0)
	// 2 批高膨胀后恢复正常，streak 清零，不应中止
	for i := 0; i < 2; i++ {
		if safe, _ := mon.Observe(100, 60000); !safe {
			t.Fatalf("early batch should not abort: %s", mon.AbortReason())
		}
	}
	for i := 0; i < 10; i++ {
		if safe, _ := mon.Observe(10000, 10000); !safe {
			t.Fatalf("normal batch should not abort: %s", mon.AbortReason())
		}
	}
}

func TestGZBNegativeDelta(t *testing.T) {
	mon := NewGZBMonitor(DefaultGZBPolicy(), 0)
	if safe, _ := mon.Observe(-1, 10); safe {
		t.Fatal("negative delta must abort")
	}
}

func TestGZBZeroInputWithOutput(t *testing.T) {
	mon := NewGZBMonitor(DefaultGZBPolicy(), 0)
	if safe, _ := mon.Observe(0, 100); safe {
		t.Fatal("output without any compressed input is infinite ratio")
	}
}

func TestGZBNestedEncoding(t *testing.T) {
	pol := DefaultGZBPolicy()
	if safe, _ := GZBCheckEncodingLayers("gzip, gzip", pol); safe {
		t.Fatal("nested gzip should be rejected")
	}
}

func TestGZBSingleEncoding(t *testing.T) {
	pol := DefaultGZBPolicy()
	if safe, _ := GZBCheckEncodingLayers("gzip", pol); !safe {
		t.Fatal("single gzip layer should pass")
	}
}

func TestGZBNoEncoding(t *testing.T) {
	pol := DefaultGZBPolicy()
	if safe, _ := GZBCheckEncodingLayers("", pol); !safe {
		t.Fatal("empty encoding should pass")
	}
}

func TestGZBDeclaredMismatch(t *testing.T) {
	// 宽松 policy 让在线 ratio/total 不拦；实际压缩入 100000、产出 60M（比 600），
	// 但响应头谎称压缩 Content-Length=100，Finalize 应报声明长度与产出不一致。
	mon := &GZBMonitor{
		policy: GZBPolicy{MaxTotalBytes: 1 << 40, MaxCompressionRatio: 100000,
			MaxSingleBurstBytes: 1 << 30, SustainedWindowStreaks: 99,
			SustainedRatio: 1 << 30, MaxEncodingLayers: 1},
		declaredLen: 100,
	}
	if safe, reason := mon.Observe(100000, 60_000_000); !safe {
		t.Fatalf("online observe should pass under loose policy: %s", reason)
	}
	safe, fs := mon.Finalize()
	if safe || len(fs) == 0 {
		t.Fatalf("want declared length mismatch, safe=%v fs=%v", safe, fs)
	}
}

func TestGZBProducedCounter(t *testing.T) {
	mon := NewGZBMonitor(DefaultGZBPolicy(), 0)
	mon.Observe(10, 100)
	mon.Observe(10, 200)
	if mon.Produced() != 300 {
		t.Fatalf("produced counter wrong %d", mon.Produced())
	}
}
