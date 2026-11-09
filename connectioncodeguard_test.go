package main

import "testing"

func TestDecodeConnectionCodeRegression(t *testing.T) {
	// 旧实现 X 前缀不校验 0-255 / 不限制长度，下列畸形首段必须全部拒绝。
	bad := []string{
		"X999-0-0-1-63dd",  // 首段 999 越界
		"X9999-0-0-1-63dd", // 4 位数字，超限
		"X+1-0-0-1-63dd",   // 带加号
		"X-0-0-1-63dd",     // 5 段但首段只有 X（空数字）
		"A-gg-0-5-63dd",    // 非十六进制段
		"A-100-0-5-63dd",   // 段 >255
		"A-0-0-5-0",        // 端口 0
		"A-0-0-5-10000",    // 端口 >65535
		"A-0-0-5",          // 段数不足
		"A-0-0-5-63dd-x",   // 段数过多
		"Z-0-0-5-63dd",     // 未知字母前缀
		"",                 // 空串
	}
	for _, code := range bad {
		if got, why := DecodeConnectionCode(code); why == connRejectNone {
			t.Fatalf("DecodeConnectionCode(%q) should be rejected, got %q", code, got)
		}
	}
}

func TestDecodeConnectionCodeValid(t *testing.T) {
	cases := map[string]string{
		"A-0-0-5-63dd":   "10.0.0.5:25565",
		"B-10-ff-ff-63dd": "172.16.255.255:25565",
		"C-a8-1-2-63dd":  "192.168.1.2:25565",
		"D-2-3-4-1":      "1.2.3.4:1",
		"X8-8-8-8-35":    "8.8.8.8:53",
		"X0-0-0-0-63dd":  "0.0.0.0:25565",
		"X255-ff-ff-ff-ffff": "255.255.255.255:65535",
	}
	for code, want := range cases {
		got, why := DecodeConnectionCode(code)
		if why != connRejectNone {
			t.Fatalf("DecodeConnectionCode(%q) rejected: %s", code, why)
		}
		if got != want {
			t.Fatalf("DecodeConnectionCode(%q) = %q want %q", code, got, want)
		}
	}
}

func TestEncodeDecodeConnectionCodeSymmetric(t *testing.T) {
	samples := []struct {
		ip   string
		port int
	}{
		{"10.0.0.5", 25565},
		{"172.16.255.255", 25565},
		{"192.168.1.2", 25565},
		{"1.2.3.4", 1},
		{"8.8.8.8", 53},
		{"0.0.0.0", 25565},
		{"255.255.255.255", 65535},
	}
	for _, s := range samples {
		code, why := EncodeConnectionCode(s.ip, s.port)
		if why != connRejectNone {
			t.Fatalf("EncodeConnectionCode(%s,%d) rejected: %s", s.ip, s.port, why)
		}
		back, why := DecodeConnectionCode(code)
		if why != connRejectNone {
			t.Fatalf("DecodeConnectionCode(%q) rejected: %s", code, why)
		}
		want := s.ip + ":" + itoaPort(s.port)
		if back != want {
			t.Fatalf("roundtrip %s:%d -> %s -> %s want %s", s.ip, s.port, code, back, want)
		}
	}
}

func itoaPort(p int) string {
	// 测试辅助：避免在断言里再引 strconv，保持可读性。
	if p == 0 {
		return "0"
	}
	digits := ""
	for p > 0 {
		digits = string(rune('0'+p%10)) + digits
		p /= 10
	}
	return digits
}

func TestPrefixCodecSymmetric(t *testing.T) {
	for seg := 0; seg <= 255; seg++ {
		prefix, ok := encodePrefix(seg)
		if !ok {
			t.Fatalf("encodePrefix(%d) failed", seg)
		}
		got, ok := decodePrefix(prefix)
		if !ok || got != seg {
			t.Fatalf("prefix roundtrip %d -> %s -> %d(%v)", seg, prefix, got, ok)
		}
	}
}

func TestEncodeConnectionCodeRejects(t *testing.T) {
	if _, why := EncodeConnectionCode("999.1.1.1", 25565); why == connRejectNone {
		t.Fatal("invalid ip should be rejected")
	}
	if _, why := EncodeConnectionCode("10.0.0.1", 0); why == connRejectNone {
		t.Fatal("invalid port should be rejected")
	}
}
