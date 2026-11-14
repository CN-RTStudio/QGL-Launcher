package main

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
