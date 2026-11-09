package main

import (
	"testing"
)

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
