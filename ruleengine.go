package main

// ruleengine.go —— 版本 JSON「rules」条件的统一评估内核。
//
// 威胁模型：
//   version.json（含 inheritsFrom 合并后的结果）与 arguments 里的规则都来自
//   镜像站 / 第三方版本目录，属于不可信输入。它们决定：
//     1. 哪些库（Library）需要下载、进入 classpath；
//     2. 哪些 natives 要解压；
//     3. 哪些条件化 JVM / 游戏参数要拼进启动命令行。
//
//   历史上这套评估散落在两处、各写一份，且都不符合 Mojang 规则语义：
//     - shouldIncludeLib（库规则）：只判 os.name == "windows"，完全忽略
//       os.arch / os.version，也不看 features；
//     - shouldIncludeArg（参数规则）：用裸 map[string]interface{} 手工断言，
//       同样只认 windows，features 只特判 is_demo_user 且“只要出现该键就拒绝”，
//       连它的布尔值都不读（{"is_demo_user":false} 也会被误拒）。
//   两份实现各自演化，行为还不一致：
//     - 无 os 约束的规则、以及“所有规则都不适用于本机”时的默认值，两边算法不同；
//     - 在 Windows on ARM64 上，natives 的 ${arch} 被恒定替换成 "64"，会取到
//       x64 的本地库；macOS / Linux 规则库则永远按 windows 结果误选。
//
// 收口策略：
//   把规则归一化成与具体 JSON 表示无关的 generalRule，只在本文件实现一次
//   Mojang 评估语义（默认拒绝；按顺序，仅“适用于当前环境”的规则改写结论，
//   最后一条适用规则的 allow/disallow 生效）。typed 的 Library 规则与裸 map
//   的 argument 规则都翻译成 generalRule 后复用同一内核，杜绝两份实现漂移。
//   os.version 是攻击者可控的正则字符串，Go 的 regexp 是 RE2（无回溯、无
//   ReDoS），但仍限制长度并在编译失败时让该条件“不适用”，绝不放行。

import (
	"regexp"
	"runtime"
	"strings"
)

// ruleOSVersionMaxLen 限制 os.version 正则的字节长度。真实 Mojang 版本正则
// （如 `10\.5\.\d`）只有十几个字节，给到 128 足以覆盖任何合法用法。
const ruleOSVersionMaxLen = 128

// ruleEnv 是评估规则时“当前运行环境”的快照，全部用 Mojang 清单里的词表：
//   osName: windows / osx / linux
//   osArch: x86 / x64 / arm64 / arm（Mojang arch 词表）
//   osVersion: 操作系统版本字符串，供 os.version 正则匹配
//   features: 启动器实际开启的特性开关；默认应为空（非演示、无自定义分辨率）
type ruleEnv struct {
	osName    string
	osArch    string
	osVersion string
	features  map[string]bool
}

// generalRule 是与 JSON 表示解耦的规则：action 为 allow/disallow，
// cond 描述它在什么环境下才“适用”。
type generalRule struct {
	action string
	cond   ruleCondition
}

// ruleCondition 描述规则的适用条件。hasOS 为 false 表示不带 os 约束。
// osName/osArch/osVersion 为空表示该维度不约束。features 为要求满足的特性。
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

// mojangArch 把 Go 的 GOARCH 映射成 Mojang 清单里的 os.arch 词表。
//   amd64 -> x64，386 -> x86，arm64 -> arm64，arm -> arm
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
