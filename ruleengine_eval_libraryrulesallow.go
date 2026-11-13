package main

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
