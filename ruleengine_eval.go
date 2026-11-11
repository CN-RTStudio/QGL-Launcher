package main

import (
	"runtime"
	"strings"
)

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

// mojangArch 把 Go 的 GOARCH 映射成 Mojang 清单里的 os.arch 词表。
//
//	amd64 -> x64，386 -> x86，arm64 -> arm64，arm -> arm
//
// 未知架构返回空串，避免带 arch 约束的规则误命中。
func mojangArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "x86"
	case "arm64":
		return "arm64"
	case "arm":
		return "arm"
	default:
		return ""
	}
}

// currentRuleEnv 返回当前进程的规则环境。features 恒为空：启动器不提供
// 演示账号、也不经清单驱动自定义分辨率 / QuickPlay，因此任何要求这些特性
// 的条件化规则都应被正确判定为不适用。
func currentRuleEnv() ruleEnv {
	return ruleEnv{
		osName:   mojangOSName(runtime.GOOS),
		osArch:   mojangArch(runtime.GOARCH),
		features: map[string]bool{},
	}
}

// featuresSatisfied 判断清单要求的特性是否在当前环境全部满足。
//   - 没有任何特性要求 -> 满足；
//   - 要求里的值必须是布尔且与环境一致；环境未开启的特性（env 里缺键）不满足；
//   - 不可信 JSON 若给出非布尔特性值，按“无法证实”处理为不满足，而不是放行。
func featuresSatisfied(want, have map[string]bool) bool {
	for key, required := range want {
		actual, present := have[key]
		if !present || actual != required {
			return false
		}
	}
	return true
}

// osVersionMatches 对 os.version 做正则匹配。pattern 为空表示不约束版本。
// 正则过长或无法编译时返回 false（该条件不适用），调用方据此跳过此规则，
// 绝不因畸形正则而默认命中。
