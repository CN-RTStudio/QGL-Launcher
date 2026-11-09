package main

// ruleOSVersionMaxLen 限制 os.version 正则的字节长度。真实 Mojang 版本正则
// （如 `10\.5\.\d`）只有十几个字节，给到 128 足以覆盖任何合法用法。
const ruleOSVersionMaxLen = 128

// ruleEnv 是评估规则时“当前运行环境”的快照，全部用 Mojang 清单里的词表：
//
//	osName: windows / osx / linux
//	osArch: x86 / x64 / arm64 / arm（Mojang arch 词表）
//	osVersion: 操作系统版本字符串，供 os.version 正则匹配
//	features: 启动器实际开启的特性开关；默认应为空（非演示、无自定义分辨率）
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
