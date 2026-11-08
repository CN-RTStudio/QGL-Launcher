package main

import "testing"

func TestSafeThemeColorAllowed(t *testing.T) {
	for _, c := range []string{"blue", "cyan", "pink", "purple", "orange", "yellow", "green"} {
		got, reason := SafeThemeColor(c)
		if reason != configRejectNone || got != c {
			t.Fatalf("合法主题色 %q 被误拒: got=%q reason=%s", c, got, reason)
		}
	}
}

func TestSafeThemeColorTrims(t *testing.T) {
	got, reason := SafeThemeColor("  cyan ")
	if reason != configRejectNone || got != "cyan" {
		t.Fatalf("应去除首尾空白: got=%q reason=%s", got, reason)
	}
}

func TestSafeThemeColorReject(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"空串", ""},
		{"空白", "   "},
		{"大小写伪造", "CYAN"},
		{"未知颜色", "red"},
		{"注入脚本", `cyan"><script>alert(1)</script>`},
		{"带控制字符", "cy\x00an"},
		{"CSS选择器", "cyan, *{color:red}"},
		{"超长", "cyan" + repeatRune('a', 200)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := SafeThemeColor(c.in)
			if reason == configRejectNone || got != "" {
				t.Fatalf("非法主题色未被拒绝: in=%q got=%q reason=%s", c.in, got, reason)
			}
		})
	}
}

func TestSafeVersionIDAllowed(t *testing.T) {
	cases := []string{
		"1.20.4",
		"24w14a",
		"1.20.4-pre1",
		"1.21",
		"fabric-loader-0.16.5-1.20.4",
	}
	for _, id := range cases {
		got, reason := SafeVersionID(id)
		if reason != configRejectNone || got != id {
			t.Fatalf("合法版本ID %q 被误拒: got=%q reason=%s", id, got, reason)
		}
	}
}

func TestSafeVersionIDEmptyAllowed(t *testing.T) {
	got, reason := SafeVersionID("   ")
	if reason != configRejectNone || got != "" {
		t.Fatalf("空版本ID应作为合法默认态: got=%q reason=%s", got, reason)
	}
}

func TestSafeVersionIDReject(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"正斜杠穿越", "../1.20.4"},
		{"反斜杠穿越", `..\1.20.4`},
		{"带子目录", "1.20.4/natives"},
		{"NUL", "NUL"},
		{"CON设备名", "CON"},
		{"COM1设备名", "COM1"},
		{"尾点", "1.20.4."},
		{"尾空格", "1.20.4 "},
		{"纯点段", ".."},
		{"冒号ADS", "1.20.4:secret"},
		{"NUL截断", "1.20.4\x00"},
		{"超长", repeatRune('a', maxVersionIDLen+1)},
		{"管道符", "1.20|rm"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := SafeVersionID(c.in)
			if reason == configRejectNone || got != "" {
				t.Fatalf("非法版本ID未被拒绝: in=%q got=%q reason=%s", c.in, got, reason)
			}
		})
	}
}

// repeatRune 返回 n 个字符 a 组成的字符串，供测试构造超长输入。
func repeatRune(a byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = a
	}
	return string(b)
}
