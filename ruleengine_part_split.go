package main

import (
	"strings"
)

func libraryRulesAllow(rules []Rule, env ruleEnv) bool {
	if len(rules) == 0 {
		return true
	}
	general := make([]generalRule, 0, len(rules))
	for _, r := range rules {
		general = append(general, libraryRuleToGeneral(r))
	}
	return rulesAllow(general, env)
}

// argumentRulesFromMap 解析 arguments 数组里“条件化参数对象”的 rules 字段。
// 入参是已被 encoding/json 解析成 map[string]interface{} 的单个规则数组原始值；
// 任何断言失败都安全跳过（畸形规则不应使整条参数被无条件放行）。
func argumentRulesFromMap(rulesRaw interface{}) []generalRule {
	arr, ok := rulesRaw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]generalRule, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		action, _ := m["action"].(string)
		gr := generalRule{action: action}
		if osRaw, hasOS := m["os"]; hasOS {
			if osMap, ok := osRaw.(map[string]interface{}); ok {
				gr.cond.hasOS = true
				gr.cond.osName, _ = osMap["name"].(string)
				gr.cond.osArch, _ = osMap["arch"].(string)
				gr.cond.osVersion, _ = osMap["version"].(string)
			}
		}
		if featRaw, hasFeatures := m["features"]; hasFeatures {
			if featMap, ok := featRaw.(map[string]interface{}); ok {
				gr.cond.features = make(map[string]bool, len(featMap))
				for k, v := range featMap {
					// 只接受布尔特性；非布尔值不写入，等同于无法证实。
					if b, isBool := v.(bool); isBool {
						gr.cond.features[k] = b
					}
				}
			}
		}
		out = append(out, gr)
	}
	return out
}

// argumentObjectAllowed 评估一个条件化参数对象（含 rules）在当前环境是否应加入。
// 没有 rules 字段 / rules 不是数组时视为无条件包含。
func argumentObjectAllowed(arg map[string]interface{}, env ruleEnv) bool {
	rulesRaw, hasRules := arg["rules"]
	if !hasRules {
		return true
	}
	general := argumentRulesFromMap(rulesRaw)
	if len(general) == 0 {
		// 有 rules 字段但解析不出任何有效规则：与 Mojang“无规则适用则拒绝”一致，
		// 不把畸形对象无条件放行进命令行。
		return false
	}
	return rulesAllow(general, env)
}

// nativeArchToken 返回当前架构下 natives 分类器 ${arch} 占位符的替换值。
// Mojang 老版 natives 映射用 ${arch} 取 "32" / "64"；arm64 不使用该占位符
// （新版清单直接给 windows-arm64 之类的独立键，见 resolveWindowsNativeKey）。
func nativeArchToken(env ruleEnv) string {
	switch env.osArch {
	case "x86":
		return "32"
	case "arm64":
		return "arm64"
	default: // x64 及其它 64 位环境按历史惯例取 64
		return "64"
	}
}

// resolveWindowsNativeKey 从版本清单的 natives 映射里选出当前 Windows 架构
// 对应的分类器键名，并完成 ${arch} 占位替换。
//
// 选择优先级（按当前架构）：
//
//	x64:   windows-64 -> windows
//	x86:   windows-x86 -> windows（${arch}=32）
//	arm64: windows-arm64 -> windows-64 -> windows（后两者靠 x64 模拟兜底）
//
// 找不到任何候选时返回 ("", false)，调用方跳过该 native。
func resolveWindowsNativeKey(natives map[string]string, env ruleEnv) (string, bool) {
	if len(natives) == 0 {
		return "", false
	}
	var candidates []string
	switch env.osArch {
	case "arm64":
		candidates = []string{"windows-arm64", "windows-64", "windows"}
	case "x86":
		candidates = []string{"windows-x86", "windows"}
	default:
		candidates = []string{"windows-64", "windows"}
	}
	token := nativeArchToken(env)
	for _, key := range candidates {
		if raw, ok := natives[key]; ok && raw != "" {
			return strings.ReplaceAll(raw, "${arch}", token), true
		}
	}
	return "", false
}
