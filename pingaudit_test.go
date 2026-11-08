package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func pingPayload(t *testing.T, value map[string]interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

func TestAuditServerPingPayloadValid(t *testing.T) {
	raw := pingPayload(t, map[string]interface{}{
		"version": map[string]interface{}{"name": "1.20.4", "protocol": 765},
		"players": map[string]interface{}{"online": 7, "max": 20},
		"description": map[string]interface{}{
			"text":  "欢迎来到 ",
			"extra": []interface{}{map[string]interface{}{"text": "服务器"}, "!"},
		},
	})
	audit := AuditServerPingPayload(raw, 42)
	if audit.Reason != pingReasonOK {
		t.Fatalf("expected ok, got %s", audit.Reason)
	}
	if audit.Version != "1.20.4" || audit.Protocol != 765 {
		t.Fatalf("version fields lost: %+v", audit)
	}
	if audit.Online != 7 || audit.Max != 20 {
		t.Fatalf("player fields lost: %+v", audit)
	}
	if audit.Motd != "欢迎来到 服务器!" {
		t.Fatalf("motd flatten mismatch: %q", audit.Motd)
	}
	if audit.LatencyMS != 42 || len(audit.Warnings) != 0 {
		t.Fatalf("unexpected latency or warnings: %+v", audit)
	}
}

func TestAuditServerPingPayloadStripsTerminalSequences(t *testing.T) {
	raw := pingPayload(t, map[string]interface{}{
		"version":     map[string]interface{}{"name": "1.20.4"},
		"players":     map[string]interface{}{"online": 0, "max": 0},
		"description": "\x1b[31mred\x1b[0m \u202eevil",
	})
	audit := AuditServerPingPayload(raw, 1)
	if audit.Reason != pingReasonOK {
		t.Fatalf("expected ok, got %s", audit.Reason)
	}
	if strings.ContainsRune(audit.Motd, 0x1b) || strings.ContainsRune(audit.Motd, 0x202e) {
		t.Fatalf("motd still carries escape or bidi characters: %q", audit.Motd)
	}
}

func TestAuditServerPingPayloadFaviconRejected(t *testing.T) {
	raw := pingPayload(t, map[string]interface{}{
		"version": map[string]interface{}{"name": "1.20.4"},
		"players": map[string]interface{}{"online": 2, "max": 10},
		"favicon": "https://evil.example/favicon.png",
	})
	audit := AuditServerPingPayload(raw, 5)
	if audit.FaviconAccepted {
		t.Fatalf("http favicon must not be accepted")
	}
	if len(audit.Warnings) == 0 {
		t.Fatalf("expected favicon warning")
	}
}

func TestAuditServerPingPayloadRejectsBadInput(t *testing.T) {
	cases := []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"empty", nil, pingReasonEmpty},
		{"too large", []byte(strings.Repeat("a", pingPayloadMaxBytes+1)), pingReasonTooLarge},
		{"bad json", []byte("{"), pingReasonBadJSON},
		{"array shape", []byte("[]"), pingReasonBadShape},
		{"no version", []byte(`{"players":{"online":0,"max":0}}`), pingReasonNoVersion},
		{"no players", []byte(`{"version":{"name":"1.20"}}`), pingReasonBadPlayers},
		{"negative online", []byte(`{"version":{"name":"1.20"},"players":{"online":-1,"max":10}}`), pingReasonBadPlayers},
		{"fractional max", []byte(`{"version":{"name":"1.20"},"players":{"online":1,"max":1.5}}`), pingReasonBadPlayers},
	}
	for _, tc := range cases {
		audit := AuditServerPingPayload(tc.raw, 0)
		if audit.Reason != tc.reason {
			t.Fatalf("%s: expected %s, got %s", tc.name, tc.reason, audit.Reason)
		}
	}
}

func TestAuditServerPingPayloadClampsCountsAndLatency(t *testing.T) {
	raw := pingPayload(t, map[string]interface{}{
		"version": map[string]interface{}{"name": "1.20.4"},
		"players": map[string]interface{}{"online": 5000000, "max": 20},
	})
	audit := AuditServerPingPayload(raw, 90000)
	if audit.Reason != pingReasonOK {
		t.Fatalf("expected ok, got %s", audit.Reason)
	}
	if audit.Online != pingPlayerCountLimit {
		t.Fatalf("online count not clamped: %d", audit.Online)
	}
	if audit.LatencyMS != pingLatencyLimitMS {
		t.Fatalf("latency not clamped: %d", audit.LatencyMS)
	}
	if len(audit.Warnings) < 2 {
		t.Fatalf("expected online/latency warnings, got %v", audit.Warnings)
	}
}

func TestAuditServerPingPayloadLongDescriptionTruncated(t *testing.T) {
	raw := pingPayload(t, map[string]interface{}{
		"version":     map[string]interface{}{"name": "1.20.4"},
		"players":     map[string]interface{}{"online": 0, "max": 0},
		"description": strings.Repeat("家", pingMotdMaxRunes+50),
	})
	audit := AuditServerPingPayload(raw, 3)
	if len([]rune(audit.Motd)) > pingMotdMaxRunes+len([]rune(motdTruncateMarker)) {
		t.Fatalf("motd not truncated: %d runes", len([]rune(audit.Motd)))
	}
}

func TestDescribeServerPingAudit(t *testing.T) {
	audit := AuditServerPingPayload([]byte("null"), 0)
	summary := DescribeServerPingAudit(audit)
	if !strings.Contains(summary, "reason="+pingReasonBadShape) {
		t.Fatalf("summary missing reason: %s", summary)
	}
}
