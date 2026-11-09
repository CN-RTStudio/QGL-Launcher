package main

import (
	"testing"
)

func TestArgumentRulesFromMapSkipsGarbage(t *testing.T) {
	if got := argumentRulesFromMap(nil); len(got) != 0 {
		t.Fatalf("nil 应解析出 0 条, got %d", len(got))
	}
	if got := argumentRulesFromMap("not-array"); len(got) != 0 {
		t.Fatalf("非数组应解析出 0 条, got %d", len(got))
	}
	raw := []interface{}{
		"not-an-object",
		map[string]interface{}{
			"action": "allow",
			"os":     map[string]interface{}{"name": "windows", "arch": "x64", "version": `10\.\d+`},
		},
		map[string]interface{}{
			"action":   "disallow",
			"features": map[string]interface{}{"is_demo_user": true},
		},
	}
	got := argumentRulesFromMap(raw)
	if len(got) != 2 {
		t.Fatalf("应跳过非对象元素得到 2 条, got %d", len(got))
	}
	if !got[0].cond.hasOS || got[0].cond.osName != "windows" || got[0].cond.osArch != "x64" {
		t.Fatalf("第一条 os 条件解析错误: %+v", got[0].cond)
	}
	if got[0].cond.osVersion != `10\.\d+` {
		t.Fatalf("version 正则未保留: %q", got[0].cond.osVersion)
	}
	if got[1].cond.features["is_demo_user"] != true {
		t.Fatal("第二条 features 解析错误")
	}
}

func TestNativeArchToken(t *testing.T) {
	cases := map[string]string{
		"x64":   "64",
		"x86":   "32",
		"arm64": "arm64",
		"":      "64",
	}
	for arch, want := range cases {
		if got := nativeArchToken(ruleEnv{osArch: arch}); got != want {
			t.Errorf("nativeArchToken(%q)=%q want %q", arch, got, want)
		}
	}
}

func TestResolveWindowsNativeKey(t *testing.T) {
	natives := map[string]string{
		"windows":       "natives-windows-${arch}",
		"windows-64":    "natives-windows-x86_64",
		"windows-x86":   "natives-windows-x86",
		"windows-arm64": "natives-windows-arm64",
	}

	x64 := ruleEnv{osName: "windows", osArch: "x64"}
	if k, ok := resolveWindowsNativeKey(natives, x64); !ok || k != "natives-windows-x86_64" {
		t.Fatalf("x64 应优先 windows-64, got %q ok=%v", k, ok)
	}

	x86 := ruleEnv{osName: "windows", osArch: "x86"}
	if k, ok := resolveWindowsNativeKey(natives, x86); !ok || k != "natives-windows-x86" {
		t.Fatalf("x86 应选 windows-x86, got %q ok=%v", k, ok)
	}

	arm := ruleEnv{osName: "windows", osArch: "arm64"}
	if k, ok := resolveWindowsNativeKey(natives, arm); !ok || k != "natives-windows-arm64" {
		t.Fatalf("arm64 应优先 windows-arm64, got %q ok=%v", k, ok)
	}

	// 只有老 windows 单键时，各架构回退到它并正确替换 ${arch}。
	legacy := map[string]string{"windows": "nw-${arch}"}
	if k, ok := resolveWindowsNativeKey(legacy, x64); !ok || k != "nw-64" {
		t.Fatalf("x64 回退单键应替换成 nw-64, got %q", k)
	}
	if k, ok := resolveWindowsNativeKey(legacy, x86); !ok || k != "nw-32" {
		t.Fatalf("x86 回退单键应替换成 nw-32, got %q", k)
	}

	// arm64 无独立键时回退 windows-64，再回退 windows（x64 模拟兜底）。
	armFallback := map[string]string{"windows-64": "nw-x86_64"}
	if k, ok := resolveWindowsNativeKey(armFallback, arm); !ok || k != "nw-x86_64" {
		t.Fatalf("arm64 应回退 windows-64, got %q ok=%v", k, ok)
	}

	if _, ok := resolveWindowsNativeKey(nil, x64); ok {
		t.Fatal("空 natives 映射应返回 false")
	}
}
