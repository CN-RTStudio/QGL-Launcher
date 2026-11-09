package main

import "testing"

func TestAuditDownloadQueueNameAccepts(t *testing.T) {
	cases := []string{
		"1.20.1",
		"1.20.1 (Forge)",
		"Forge 47.2.0",
		"整合包 v2",
		"java-17",
		"a b c",
		"1.20.1-rc1",
	}
	for _, name := range cases {
		if got := auditDownloadQueueName(name); got != dqNameRejectNone {
			t.Fatalf("auditDownloadQueueName(%q)=%q want none", name, got)
		}
	}
}

func TestAuditDownloadQueueNameRejects(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"", dqNameRejectEmpty},
		{"../../etc/passwd", dqNameRejectSeparator},
		{"a\\b", dqNameRejectSeparator},
		{"C:evil", dqNameRejectSeparator},
		{"a:b", dqNameRejectSeparator},
		{"x\x00y", dqNameRejectControl},
		{"x\ny", dqNameRejectControl},
		{"x\x7fy", dqNameRejectControl},
		{"CON", dqNameRejectReserved},
		{"con.txt", dqNameRejectReserved},
		{"NUL", dqNameRejectReserved},
		{"COM1", dqNameRejectReserved},
		{"LPT9.log", dqNameRejectReserved},
		{"setup.exe ", dqNameRejectTrailing},
		{"setup.exe.", dqNameRejectTrailing},
		{"...", dqNameRejectTrailing},
		{repeatAscii(maxDownloadQueueNameLen + 1), dqNameRejectLong},
	}
	for _, c := range cases {
		if got := auditDownloadQueueName(c.name); got != c.want {
			t.Fatalf("auditDownloadQueueName(%q)=%q want %q", c.name, got, c.want)
		}
	}
}

func TestDescribeDownloadNameReject(t *testing.T) {
	codes := []string{
		dqNameRejectEmpty, dqNameRejectLong, dqNameRejectControl, dqNameRejectSeparator,
		dqNameRejectTraversal, dqNameRejectReserved, dqNameRejectTrailing,
	}
	seen := map[string]bool{}
	for _, code := range codes {
		text := describeDownloadNameReject(code)
		if text == "" {
			t.Fatalf("empty text for %q", code)
		}
		if seen[text] {
			t.Fatalf("duplicate text %q", text)
		}
		seen[text] = true
	}
	if got := describeDownloadNameReject("unknown"); got == "" {
		t.Fatalf("fallback text is empty")
	}
}

func TestDownloadQueueRejectsUnsafeName(t *testing.T) {
	base := DownloadItem{ID: "x", ItemType: "game", CustomName: "1.20.1", URL: "https://example.test/1.20.1.json"}
	if why := auditDownloadItemForEnqueue(nil, base); why != dqRejectNone {
		t.Fatalf("safe item rejected: %q", why)
	}
	for _, name := range []string{"CON", "a/b", "x."} {
		item := base
		item.CustomName = name
		if why := auditDownloadItemForEnqueue(nil, item); why != dqRejectBadName {
			t.Fatalf("unsafe name %q got %q want %q", name, why, dqRejectBadName)
		}
	}
}
