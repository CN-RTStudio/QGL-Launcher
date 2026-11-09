package main

import (
	"testing"
)

func TestMojangOSName(t *testing.T) {
	cases := map[string]string{
		"windows": "windows",
		"darwin":  "osx",
		"linux":   "linux",
		"js":      "",
		"":        "",
	}
	for in, want := range cases {
		if got := mojangOSName(in); got != want {
			t.Errorf("mojangOSName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMojangArch(t *testing.T) {
	cases := map[string]string{
		"amd64": "x64",
		"386":   "x86",
		"arm64": "arm64",
		"arm":   "arm",
		"riscv": "",
	}
	for in, want := range cases {
		if got := mojangArch(in); got != want {
			t.Errorf("mojangArch(%q)=%q want %q", in, got, want)
		}
	}
}

func TestFeaturesSatisfied(t *testing.T) {
	env := map[string]bool{}
	if !featuresSatisfied(nil, env) {
		t.Fatal("空特性要求应满足")
	}
	// 环境未开启任何特性：要求 is_demo_user=true 不满足。
	if featuresSatisfied(map[string]bool{"is_demo_user": true}, env) {
		t.Fatal("未开启演示时要求演示应不满足")
	}
	// 显式要求 false 时，“环境没有该特性”等价于 false，应满足。
	// 这是旧裸 map 实现的回归点：它只要看到 is_demo_user 键就拒绝，连值都不读。
	if !featuresSatisfied(map[string]bool{"is_demo_user": false}, env) {
		t.Fatal("要求 is_demo_user=false 且环境非演示时应满足")
	}
	opened := map[string]bool{"has_custom_resolution": true}
	if !featuresSatisfied(map[string]bool{"has_custom_resolution": true}, opened) {
		t.Fatal("环境已开启且要求 true 应满足")
	}
	if featuresSatisfied(map[string]bool{"has_custom_resolution": false}, opened) {
		t.Fatal("环境已开启而要求 false 应不满足")
	}
}

func TestOSVersionMatches(t *testing.T) {
	if !osVersionMatches("", "anything") {
		t.Fatal("空 pattern 应视为不约束并匹配")
	}
	if !osVersionMatches(`10\.5\.\d+`, "10.5.9") {
		t.Fatal("合法正则应匹配")
	}
	if osVersionMatches(`10\.5\.\d+`, "10.6.0") {
		t.Fatal("不匹配的版本正则应返回 false")
	}
	if osVersionMatches(`[`, "10.0") {
		t.Fatal("非法正则应安全失败为不匹配")
	}
	long := ""
	for i := 0; i < ruleOSVersionMaxLen+1; i++ {
		long += "a"
	}
	if osVersionMatches(long, "") {
		t.Fatal("超长正则应安全失败为不匹配")
	}
}

func TestOSConditionMatches(t *testing.T) {
	env := ruleEnv{osName: "windows", osArch: "x64", osVersion: "10.0"}
	if !osConditionMatches(ruleCondition{}, env) {
		t.Fatal("全空 os 条件应匹配")
	}
	if !osConditionMatches(ruleCondition{osName: "Windows", osArch: "X64"}, env) {
		t.Fatal("name/arch 应大小写不敏感匹配")
	}
	if osConditionMatches(ruleCondition{osName: "osx"}, env) {
		t.Fatal("osx 条件不应在 windows 环境命中")
	}
	if osConditionMatches(ruleCondition{osArch: "arm64"}, env) {
		t.Fatal("arm64 条件不应在 x64 环境命中")
	}
	arm := ruleEnv{osName: "windows", osArch: "arm64"}
	if !osConditionMatches(ruleCondition{osName: "windows", osArch: "arm64"}, arm) {
		t.Fatal("arm64 条件应在 arm64 环境命中")
	}
}
