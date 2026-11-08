package main

import "testing"

func TestNormalizeGameFlag(t *testing.T) {
	cases := []struct {
		in        string
		name      string
		separated bool
		ok        bool
	}{
		{"--server", "server", true, true},
		{"-port", "port", true, true},
		{"--accessToken=x", "accesstoken", false, true},
		{"--width", "width", true, true},
		{"plain", "", false, false},
		{"-", "", false, false},
		{"--", "", false, false},
	}
	for _, c := range cases {
		name, separated, ok := normalizeGameFlag(c.in)
		if name != c.name || separated != c.separated || ok != c.ok {
			t.Fatalf("normalizeGameFlag(%q)=(%q,%v,%v) want (%q,%v,%v)",
				c.in, name, separated, ok, c.name, c.separated, c.ok)
		}
	}
}

func TestAuditExternalGameArgsAllowsNormal(t *testing.T) {
	in := []string{"--demo", "--fullscreen", "someValue", "--tweakOrder=1"}
	g := AuditExternalGameArgs(in)
	if g.HasCritical() {
		t.Fatalf("正常业务参数应放行，首个 code=%s", g.FirstCriticalCode())
	}
	if len(g.SafeExternal) != len(in) {
		t.Fatalf("应保留全部 %d 条，实际 %d", len(in), len(g.SafeExternal))
	}
}

func TestAuditExternalGameArgsAllowsOfficialPlaceholders(t *testing.T) {
	// 官方版本 JSON 本来就携带这些占位 flag，值由启动器替换，不能误杀。
	in := []string{
		"--username", "${auth_player_name}",
		"--version", "${version_name}",
		"--gameDir", "${game_directory}",
		"--accessToken", "${auth_access_token}",
		"--uuid", "${auth_uuid}",
		"--userType", "${user_type}",
		"--versionType", "${version_type}",
		"--width", "${resolution_width}",
		"--height", "${resolution_height}",
	}
	g := AuditExternalGameArgs(in)
	if g.HasCritical() {
		t.Fatalf("官方占位参数应放行，首个 code=%s", g.FirstCriticalCode())
	}
	if len(g.SafeExternal) != len(in) {
		t.Fatalf("应保留全部 %d 条占位参数，实际 %d", len(in), len(g.SafeExternal))
	}
}

func TestAuditExternalGameArgsStripsHijack(t *testing.T) {
	in := []string{
		"--demo",
		"--server", "evil-relay.example", // 分离式：服务器地址载荷也要吞掉
		"--fullscreen",
		"--quickPlayMultiplayer=evil-relay.example", // 自携带值
		"--port", "25565",
	}
	g := AuditExternalGameArgs(in)
	if !g.HasCritical() {
		t.Fatal("会话劫持参数应判 critical")
	}
	if code := g.FirstCriticalCode(); code != "ga-hijack-flag" {
		t.Fatalf("首个 code 应为 ga-hijack-flag，实际 %s", code)
	}
	want := map[string]bool{"--demo": true, "--fullscreen": true}
	if len(g.SafeExternal) != len(want) {
		t.Fatalf("安全参数应为 2 条，实际 %d: %v", len(g.SafeExternal), g.SafeExternal)
	}
	for _, s := range g.SafeExternal {
		if !want[s] {
			t.Fatalf("不应保留参数 %q", s)
		}
	}
	if g.Rejected != 5 { // --server/主机/--quickPlay.../--port/端口 五条全部剔除
		t.Fatalf("应拒绝 5 条，实际 %d", g.Rejected)
	}
}

func TestAuditExternalGameArgsRejectedCount(t *testing.T) {
	in := []string{"--server", "evil", "--port", "25565", "--quickPlayMultiplayer", "evil"}
	g := AuditExternalGameArgs(in)
	// 三个分离式劫持 flag 与其操作数，共 6 条全部拒绝。
	if g.Rejected != 6 {
		t.Fatalf("应拒绝 6 条，实际 %d", g.Rejected)
	}
	if len(g.SafeExternal) != 0 {
		t.Fatalf("不应有安全参数，实际 %v", g.SafeExternal)
	}
}

func TestAuditExternalGameArgsControlAndLong(t *testing.T) {
	g1 := AuditExternalGameArgs([]string{"bad\ntoken"})
	if !gameFindingsHasCode(g1.Findings, "ga-control") {
		t.Fatal("含换行的值应命中 ga-control")
	}
	big := make([]byte, maxGameArgValueBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	g2 := AuditExternalGameArgs([]string{string(big)})
	if !gameFindingsHasCode(g2.Findings, "ga-long") {
		t.Fatal("超长值应命中 ga-long")
	}
	// 被吞掉的操作数若含控制字符也要拒绝，而不是误放行。
	g3 := AuditExternalGameArgs([]string{"--server", "evil\nhost", "--fullscreen"})
	if !gameFindingsHasCode(g3.Findings, "ga-control") {
		t.Fatal("保留参数的操作数含换行应命中 ga-control")
	}
	if len(g3.SafeExternal) != 1 || g3.SafeExternal[0] != "--fullscreen" {
		t.Fatalf("应仅保留 --fullscreen，实际 %v", g3.SafeExternal)
	}
}

func TestAuditExternalGameArgsTooMany(t *testing.T) {
	in := make([]string, maxExternalGameArgs+2)
	for i := range in {
		in[i] = "--flag" + itoaForTest(i)
	}
	g := AuditExternalGameArgs(in)
	if !gameFindingsHasCode(g.Findings, "ga-too-many") {
		t.Fatal("参数条数超限应命中 ga-too-many")
	}
}

func TestAuditReservedGameValues(t *testing.T) {
	ok := AuditReservedGameValues(map[string]string{
		"--server": "mc.example.com",
		"--port":   "25565",
		"--empty":  "",
	})
	if ok.HasCritical() {
		t.Fatalf("正常保留值应通过，首个 code=%s", ok.FirstCriticalCode())
	}
	bad := AuditReservedGameValues(map[string]string{
		"--server": "mc\n.example",
	})
	if !gameFindingsHasCode(bad.Findings, "ga-reserved-control") {
		t.Fatal("保留值含换行应命中 ga-reserved-control")
	}
	bigVal := string(make([]byte, maxGameArgValueBytes+1))
	bad2 := AuditReservedGameValues(map[string]string{"--server": bigVal})
	if !gameFindingsHasCode(bad2.Findings, "ga-reserved-long") {
		t.Fatal("超长保留值应命中 ga-reserved-long")
	}
}
