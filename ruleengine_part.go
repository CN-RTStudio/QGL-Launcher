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
