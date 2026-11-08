package main

import "testing"

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

func TestEvaluateRules(t *testing.T) {
	win := ruleEnv{osName: "windows", osArch: "x64", features: map[string]bool{}}
	osx := ruleEnv{osName: "osx", osArch: "arm64", features: map[string]bool{}}

	// 空规则：ok=false，交给调用方默认。
	if _, ok := evaluateRules(nil, win); ok {
		t.Fatal("空规则应返回 ok=false")
	}

	// 仅允许 osx：windows 上没有适用规则 -> 拒绝。
	rules := []generalRule{{action: "allow", cond: ruleCondition{hasOS: true, osName: "osx"}}}
	if got, ok := evaluateRules(rules, win); !ok || got {
		t.Fatalf("osx-only 规则在 windows 应拒绝, got=%v ok=%v", got, ok)
	}
	if got, ok := evaluateRules(rules, osx); !ok || !got {
		t.Fatalf("osx-only 规则在 osx 应允许, got=%v ok=%v", got, ok)
	}

	// 默认允许 windows，随后 disallow 覆盖。
	rules = []generalRule{
		{action: "allow"},
		{action: "disallow", cond: ruleCondition{hasOS: true, osName: "windows", osArch: "x86"}},
	}
	if !rulesAllow(rules, win) {
		t.Fatal("x64 环境：x86 disallow 不适用，应保持允许")
	}
	winx86 := ruleEnv{osName: "windows", osArch: "x86", features: map[string]bool{}}
	if rulesAllow(rules, winx86) {
		t.Fatal("x86 环境：disallow 适用，应覆盖为拒绝")
	}

	// 未知 action 不应改变结论，也不应被当成适用规则。
	rules = []generalRule{
		{action: "wat", cond: ruleCondition{hasOS: true, osName: "osx"}},
	}
	if rulesAllow(rules, win) {
		t.Fatal("只有未知 action 且对本机不适用时应拒绝")
	}
}

func TestLibraryRulesAllow(t *testing.T) {
	win := currentRuleEnv() // 测试在真实机器上跑，平台自洽。
	if !libraryRulesAllow(nil, win) {
		t.Fatal("库无规则应包含")
	}
	// 只允许另一个平台的库在本机应被排除（除非本机恰是该平台，则用自洽断言）。
	other := "osx"
	if win.osName == "osx" {
		other = "linux"
	}
	rules := []Rule{{Action: "allow", OS: &RuleOS{Name: other}}}
	if libraryRulesAllow(rules, win) {
		t.Fatalf("只允许 %s 的库不应在 %s 上包含", other, win.osName)
	}

	// arch 维度：要求 arm64 的库在 x64 上排除。
	if win.osArch == "x64" {
		rules = []Rule{{Action: "allow", OS: &RuleOS{Name: "windows", Arch: "arm64"}}}
		if libraryRulesAllow(rules, win) {
			t.Fatal("要求 arm64 的库不应在 x64 包含")
		}
	}

	// features 维度：要求演示用户的库在非演示环境排除。
	rules = []Rule{{Action: "allow", Features: map[string]bool{"is_demo_user": true}}}
	if libraryRulesAllow(rules, win) {
		t.Fatal("要求演示特性的库在非演示环境应排除")
	}
}

func TestArgumentObjectAllowed(t *testing.T) {
	win := currentRuleEnv()
	other := "osx"
	if win.osName == "osx" {
		other = "linux"
	}

	// 无 rules 字段：无条件加入。
	if !argumentObjectAllowed(map[string]interface{}{"value": "-Xmx1G"}, win) {
		t.Fatal("无 rules 参数应加入")
	}

	// 空 rules 数组：没有适用规则，按 Mojang 语义拒绝。
	if argumentObjectAllowed(map[string]interface{}{"rules": []interface{}{}}, win) {
		t.Fatal("空 rules 数组应拒绝")
	}

	// is_demo_user=false（旧实现回归点）：环境非演示，应加入。
	obj := map[string]interface{}{
		"rules": []interface{}{
			map[string]interface{}{
				"action": "allow",
				"features": map[string]interface{}{
					"is_demo_user": false,
				},
			},
		},
	}
	if !argumentObjectAllowed(obj, win) {
		t.Fatal("is_demo_user=false 在非演示环境应允许（旧实现误拒）")
	}

	// is_demo_user=true：非演示环境拒绝。
	obj = map[string]interface{}{
		"rules": []interface{}{
			map[string]interface{}{
				"action":   "allow",
				"features": map[string]interface{}{"is_demo_user": true},
			},
		},
	}
	if argumentObjectAllowed(obj, win) {
		t.Fatal("is_demo_user=true 在非演示环境应拒绝")
	}

	// 只面向另一个平台的参数应在本机排除。
	obj = map[string]interface{}{
		"rules": []interface{}{
			map[string]interface{}{
				"action": "allow",
				"os":     map[string]interface{}{"name": other},
			},
		},
	}
	if argumentObjectAllowed(obj, win) {
		t.Fatalf("面向 %s 的参数不应在 %s 加入", other, win.osName)
	}

	// 非布尔特性值：无法证实，规则不适用 -> 拒绝。
	obj = map[string]interface{}{
		"rules": []interface{}{
			map[string]interface{}{
				"action":   "allow",
				"features": map[string]interface{}{"is_demo_user": "yes"},
			},
		},
	}
	if argumentObjectAllowed(obj, win) {
		t.Fatal("非布尔特性值应安全拒绝")
	}
}

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
