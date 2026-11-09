package main

import (
	"regexp"
	"strings"
)

func osVersionMatches(pattern, actual string) bool {
	if pattern == "" {
		return true
	}
	if len(pattern) > ruleOSVersionMaxLen {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(actual)
}

// osConditionMatches 判断 os 维度（name/arch/version）是否与环境一致。
// 各字段为空表示该维度不约束；name/arch 大小写不敏感比较（Mojang 词表均小写，
// 这里顺手做归一化，避免镜像站写成 Windows/X64 时漏判）。
func osConditionMatches(cond ruleCondition, env ruleEnv) bool {
	if cond.osName != "" && !strings.EqualFold(cond.osName, env.osName) {
		return false
	}
	if cond.osArch != "" && !strings.EqualFold(cond.osArch, env.osArch) {
		return false
	}
	if !osVersionMatches(cond.osVersion, env.osVersion) {
		return false
	}
	return true
}

// conditionApplies 判断一条规则在当前环境是否“适用”：
// 不带 os 约束时不校验系统；带 os 约束则 name/arch/version 必须全部命中；
// features 必须全部满足。返回 (是否适用, 条件本身是否有效)。
// 当条件内部自相矛盾 / 无法判定时返回 false，由调用方跳过该规则。
func conditionApplies(cond ruleCondition, env ruleEnv) bool {
	if cond.hasOS && !osConditionMatches(cond, env) {
		return false
	}
	if !featuresSatisfied(cond.features, env.features) {
		return false
	}
	return true
}

// evaluateRules 实现 Mojang 的规则合成语义：
//   - 没有任何规则时默认“不适用判定”，由调用方按自身默认处理
//     （库无规则应包含，参数无规则应包含），因此本函数返回 ok=false；
//   - 有规则但没有一条适用于当前环境 -> 拒绝（allowed=false, ok=true）；
//   - 否则按出现顺序，仅适用的规则改写结论，最后一条适用规则的 action 决定；
//   - action 只认 allow/disallow，其它（含空串）忽略，不改变当前结论。
func evaluateRules(rules []generalRule, env ruleEnv) (allowed, ok bool) {
	if len(rules) == 0 {
		return false, false
	}
	result := false
	applicable := false
	for _, r := range rules {
		if !conditionApplies(r.cond, env) {
			continue
		}
		switch r.action {
		case "allow":
			result = true
			applicable = true
		case "disallow":
			result = false
			applicable = true
		default:
			// 未知 action 不是有效的适用规则，忽略它。
		}
	}
	if !applicable {
		return false, true
	}
	return result, true
}

// rulesAllow 是“无规则即包含”场景的便捷封装：库、参数在没有规则时都应保留，
// 有规则时交给 Mojang 语义判定。
func rulesAllow(rules []generalRule, env ruleEnv) bool {
	allowed, ok := evaluateRules(rules, env)
	if !ok {
		return true
	}
	return allowed
}

// libraryRuleToGeneral 把 typed 的 Library 规则翻译成通用规则。
func libraryRuleToGeneral(r Rule) generalRule {
	gr := generalRule{action: r.Action}
	if r.OS != nil {
		gr.cond.hasOS = true
		gr.cond.osName = r.OS.Name
		gr.cond.osArch = r.OS.Arch
		gr.cond.osVersion = r.OS.Version
	}
	if len(r.Features) > 0 {
		gr.cond.features = r.Features
	}
	return gr
}

// libraryRulesAllow 评估一组库规则在当前环境是否应包含该库。
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
//   x64:   windows-64 -> windows
//   x86:   windows-x86 -> windows（${arch}=32）
//   arm64: windows-arm64 -> windows-64 -> windows（后两者靠 x64 模拟兜底）
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
