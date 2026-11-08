package main

import (
	"strings"
	"testing"
)

type yggProfileStub = struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func TestValidateYggProfileName(t *testing.T) {
	good := []string{"Steve", "Alex_01", "a", strings.Repeat("x", 16)}
	for _, n := range good {
		if got := validateYggProfileName(n); got != ypOK {
			t.Fatalf("合法角色名 %q 被拒: %s", n, got)
		}
	}
	bad := map[string]string{
		"":                ypNameEmpty,
		"  ":              ypNameEmpty,
		"../../evil":      ypNameChar,
		"bad name":        ypNameChar,
		"bad\"arg":        ypNameChar,
		strings.Repeat("x", 17): ypNameLen,
		"中文玩家":          ypNameChar,
		"player\ncmd":     ypNameChar,
	}
	for n, want := range bad {
		if got := validateYggProfileName(n); got != want {
			t.Fatalf("validateYggProfileName(%q) = %s, want %s", n, got, want)
		}
	}
}

func TestCanonicalYggProfileUUID(t *testing.T) {
	const flat = "069a79f444e94726a5befca90e38aaf5"
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{flat, flat, true},
		{"069a79f4-44e9-4726-a5be-fca90e38aaf5", flat, true},
		{"069A79F4-44E9-4726-A5BE-FCA90E38AAF5", flat, true},
		{"", "", false},
		{"short", "", false},
		{"069a79f4-44e9-4726-a5be-fca90e38aaf", "", false},
		{"069a79f444e94726a5befca90e38aazz", "", false},
		{"../../069a79f4", "", false},
	}
	for _, c := range cases {
		got, ok := canonicalYggProfileUUID(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("canonicalYggProfileUUID(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestValidateYggToken(t *testing.T) {
	if validateYggToken("abc123TOKEN", false) != ypOK {
		t.Fatal("普通令牌应允许")
	}
	if validateYggToken("", true) != ypOK {
		t.Fatal("允许空时 clientToken 空应通过")
	}
	if validateYggToken("", false) != ypTokenBad {
		t.Fatal("accessToken 空必须拒绝")
	}
	if validateYggToken("abc\ndef", false) != ypTokenBad {
		t.Fatal("含换行的令牌必须拒绝（防头注入）")
	}
	if validateYggToken("ab cd", false) != ypTokenBad {
		t.Fatal("含空格的令牌必须拒绝")
	}
	if validateYggToken(strings.Repeat("x", maxYggTokenLen+1), false) != ypTokenBad {
		t.Fatal("超长令牌必须拒绝")
	}
}

func TestPickYggProfile(t *testing.T) {
	mk := func(id, name string) yggProfileStub {
		return yggProfileStub{ID: id, Name: name}
	}
	const goodUUID = "069a79f444e94726a5befca90e38aaf5"

	// 优先 selected。
	sel := mk(goodUUID, "Steve")
	p, ok := pickYggProfile(&sel, []yggProfileStub{mk(goodUUID, "Other")})
	if !ok || p.Name != "Steve" || p.UUID != goodUUID {
		t.Fatalf("应优先 selected，got %+v,%v", p, ok)
	}

	// selected 非法时回退到 available 里第一个合法的。
	badSel := mk("../evil", "../../x")
	p, ok = pickYggProfile(&badSel, []yggProfileStub{
		mk("nope", "Bad"),
		mk(goodUUID, "Alex_9"),
	})
	if !ok || p.Name != "Alex_9" {
		t.Fatalf("应跳过非法 selected 找到合法 available，got %+v,%v", p, ok)
	}

	// 全部非法必须返回 false（调用方据此拒绝登录）。
	if _, ok := pickYggProfile(nil, []yggProfileStub{mk("x", "bad name")}); ok {
		t.Fatal("全部非法时不得放行")
	}
	if _, ok := pickYggProfile(nil, nil); ok {
		t.Fatal("无任何角色时不得放行")
	}

	// 带连字符 UUID 应被归一为 32 位小写。
	sel2 := mk("069A79F4-44E9-4726-A5BE-FCA90E38AAF5", "Alex")
	p, ok = pickYggProfile(&sel2, nil)
	if !ok || p.UUID != goodUUID {
		t.Fatalf("带连字符大写 UUID 应归一，got %+v,%v", p, ok)
	}
}

func TestValidateYggServerName(t *testing.T) {
	if got, ok := validateYggServerName(" LittleSkin "); !ok || got != "LittleSkin" {
		t.Fatalf("普通服务器名应通过并 trim，got %q,%v", got, ok)
	}
	if _, ok := validateYggServerName("a\nb"); ok {
		t.Fatal("含换行的服务器名必须拒绝")
	}
	if _, ok := validateYggServerName(strings.Repeat("x", maxYggServerNameLen+1)); ok {
		t.Fatal("超长服务器名必须拒绝")
	}
}

func TestDescribeYggReject(t *testing.T) {
	if describeYggReject(ypNameChar) == "" || describeYggReject("weird") == "" {
		t.Fatal("拒绝说明不应为空")
	}
}
