package main

// isEnforcedJvmProperty 报告（已小写的）属性名是否为启动器强制项。
func isEnforcedJvmProperty(lowerName string) bool {
	_, ok := enforcedJvmPropertyKeys[lowerName]
	return ok
}

// enforcedJvmPropertyArgs 返回强制属性的规范命令行片段（-Dkey=value），顺序固定。
func enforcedJvmPropertyArgs() []string {
	out := make([]string, 0, len(enforcedJvmProperties))
	for _, p := range enforcedJvmProperties {
		out = append(out, "-D"+p.key+"="+p.value)
	}
	return out
}

// applyEnforcedJvmProperties 收敛一条 JVM 参数序列：
//   - 丢弃其中所有对强制键的 -D 赋值（含无值形式与任何大小写/取值），避免外部参数
//     靠“后出现”覆盖安全值，也避免重复；
//   - 其余参数原样保留（含 -Xmx、-cp、普通 -D 等）；
//   - 在末尾追加一份规范强制属性，保证其最终生效。
//
// 入参通常只含 JVM 参数（MainClass 与游戏程序参数不要传入）。
func applyEnforcedJvmProperties(jvmArgs []string) []string {
	kept := make([]string, 0, len(jvmArgs)+len(enforcedJvmProperties))
	for _, arg := range jvmArgs {
		name, _, isProp := parseSystemPropertyArg(lowerAscii(trimSpaceArg(arg)))
		if isProp && isEnforcedJvmProperty(name) {
			continue // 强制键：任何来源的取值都不让进最终命令行
		}
		kept = append(kept, arg)
	}
	return append(kept, enforcedJvmPropertyArgs()...)
}

// trimSpaceArg 仅用于解析前折叠首尾空白；命令行片段一般无空白，保留这一步是为了
// 与 parseSystemPropertyArg 的“入参需 TrimSpace”契约一致。
func trimSpaceArg(s string) string {
	start := 0
	for start < len(s) && isASCIISpace(s[start]) {
		start++
	}
	end := len(s)
	for end > start && isASCIISpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isASCIISpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}
