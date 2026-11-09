package main

import (
	"strings"
)

func shouldIncludeArg(arg map[string]interface{}) bool {
	// 条件化参数统一走 ruleengine：裸 map 的 rules 被翻译成通用规则后按 Mojang
	// 语义评估（os.name/arch/version + features），与库过滤共用同一内核，避免
	// 两份实现漂移。旧实现只认 windows、且 features 只要出现 is_demo_user 键
	// （无论真假值）就拒绝，会把 {"is_demo_user":false} 的正常参数误删。
	return argumentObjectAllowed(arg, currentRuleEnv())
}

func deduplicateJvmArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	type argGroup struct {
		fullKey string
		parts   []string
	}
	var groups []argGroup
	current := argGroup{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if current.fullKey != "" {
				groups = append(groups, current)
			}
			current = argGroup{fullKey: arg, parts: []string{arg}}
		} else {
			current.fullKey = current.fullKey + "\x00" + arg
			current.parts = append(current.parts, arg)
		}
	}
	if current.fullKey != "" {
		groups = append(groups, current)
	}
	seen := make(map[string]bool)
	var result []string
	for _, g := range groups {
		if !seen[g.fullKey] {
			seen[g.fullKey] = true
			result = append(result, g.parts...)
		}
	}
	return result
}
