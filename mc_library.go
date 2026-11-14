package main

import (
	"strings"
)

func (a *App) shouldIncludeLib(lib Library) bool {
	// 库规则统一走 ruleengine：按 Mojang 语义评估 os.name/arch/version 与 features，
	// 不再只判 os.name=="windows"（旧逻辑会误选 osx/linux 专属库、忽略架构与版本）。
	return libraryRulesAllow(lib.Rules, currentRuleEnv())
}
func libGroupArtifact(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return name
}
