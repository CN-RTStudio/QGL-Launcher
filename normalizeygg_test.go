package main

import "testing"

// normalizeYggdrasilURL 后面紧接着会向该地址明文 POST 账号密码，因此这里的每一条
// 拒绝规则都是在守"密码发往哪台主机"。黄金用例锁定规范化结果与拒绝分支。

func TestNormalizeYggdrasilURLAppendsSuffix(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"https 公网自动补 /api/yggdrasil",
			"https://skin.example.com", "https://skin.example.com/api/yggdrasil"},
		{"已带后缀不再追加",
			"https://skin.example.com/api/yggdrasil", "https://skin.example.com/api/yggdrasil"},
		{"单个尾斜杠",
			"https://skin.example.com/", "https://skin.example.com/api/yggdrasil"},
		{"首尾空白被裁剪",
			"  https://skin.example.com  ", "https://skin.example.com/api/yggdrasil"},
		{"后缀后多个尾斜杠被收敛(历史会重复追加)",
			"https://skin.example.com/api/yggdrasil//", "https://skin.example.com/api/yggdrasil"},
		{"回环 http 调试允许并补后缀",
			"http://127.0.0.1:8080/", "http://127.0.0.1:8080/api/yggdrasil"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeYggdrasilURL(c.in)
			if err != nil {
				t.Fatalf("normalizeYggdrasilURL(%q) 意外报错: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("normalizeYggdrasilURL(%q)=%q want %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizeYggdrasilURLRejects(t *testing.T) {
	bad := []struct {
		name string
		in   string
	}{
		{"无协议", "skin.example.com"},
		{"公网明文 http", "http://skin.example.com"},
		{"userinfo 视觉混淆", "https://trusted.example@evil.test/api/yggdrasil"},
		{"userinfo 带密码", "https://trusted.example:pw@evil.test/"},
		{"空主机名", "https:///api/yggdrasil"},
		{"含回车", "https://skin.example.com\r/api/yggdrasil"},
		{"含换行", "https://skin.example.com\n"},
		{"含制表符", "https://skin.ex\tmple.com"},
		{"含 NUL", "https://skin.example.com\x00"},
		{"含 DEL", "https://skin.example.com\x7f"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if got, err := normalizeYggdrasilURL(c.in); err == nil {
				t.Fatalf("normalizeYggdrasilURL(%q) 应被拒绝，却得到 %q", c.in, got)
			}
		})
	}
}

func TestNormalizeYggdrasilURLIdempotent(t *testing.T) {
	first, err := normalizeYggdrasilURL("https://skin.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	second, err := normalizeYggdrasilURL(first)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("规范化非幂等: %q -> %q", first, second)
	}
}

func TestNormalizeYggdrasilURLObfuscatedLoopback(t *testing.T) {
	// 本地调试皮肤站用 inet_aton 短格式 http://127.1 也必须放行（归一化后补后缀）。
	got, err := normalizeYggdrasilURL("http://127.1:8080/")
	if err != nil {
		t.Fatalf("混淆回环 http 调试应放行，却被拒: %v", err)
	}
	if want := "http://127.1:8080/api/yggdrasil"; got != want {
		t.Fatalf("normalize=%q want %q", got, want)
	}
}

func TestNormalizeYggdrasilURLObfuscatedPublicRejected(t *testing.T) {
	// 单整数写成 8.8.8.8 仍是公网，明文 http 必须拒绝，不能因混淆而误判成回环放行。
	if got, err := normalizeYggdrasilURL("http://0x08080808/"); err == nil {
		t.Fatalf("混淆公网 http 应被拒绝，却得到 %q", got)
	}
}
