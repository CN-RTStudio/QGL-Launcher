package main

import (
	"runtime"
)

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
