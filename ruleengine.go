package main

import (
	"regexp"
	"strings"
)

const ruleOSVersionMaxLen = 128

type ruleEnv struct {
	osName    string
	osArch    string
	osVersion string
	features  map[string]bool
}
type generalRule struct {
	action string
	cond   ruleCondition
}

type ruleCondition struct {
	hasOS     bool
	osName    string
	osArch    string
	osVersion string
	features  map[string]bool
}

// mojangOSName 把 Go 的 GOOS 映射成 Mojang 清单里的 os.name。
// 不在三类受支持桌面系统之内时返回空串——这样任何带 os.name 约束的规则
// 都不会误命中，而不是把未知系统当成某个已知系统放行。
func mojangOSName(goos string) string {
	switch goos {
	case "windows":
		return "windows"
	case "darwin":
		return "osx"
	case "linux":
		return "linux"
	default:
		return ""
	}
}

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
