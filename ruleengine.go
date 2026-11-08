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

import "runtime"

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
