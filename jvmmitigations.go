package main

// jvmmitigations.go —— 游戏 JVM “不可被外部撤销”的安全缓解属性强制内核。
//
// 背景：buildLaunchArgs 会把启动器自带参数、版本/加载器 JSON 的 arguments.jvm
// （外部不可信数据）、加载器附加项依次拼成最终命令行。这里有两类真实缺口：
//
//  1. 缓解项可被覆盖。HotSpot 对同一个 -Dkey 以命令行里“最后一个”为准。旧实现把
//     -Dlog4j2.formatMsgNoLookups=true 放在 jvmArgs 最前面，而不可信版本 JSON 的
//     参数 append 在它后面。该属性名不在 jvmprops.go 的危险名单里（它本身无害），
//     于是一份被篡改的版本 JSON 只要带上
//     -Dlog4j2.formatMsgNoLookups=false，就能把启动器的 Log4Shell 缓解悄悄撤销。
//
//  2. 只挡了消息 lookup，没收口 JNDI 远程类加载。formatMsgNoLookups 只对
//     log4j 2.10~2.14.1 的消息解析生效，对 Thread Context Map（CVE-2021-45046）
//     等无效；而 JNDI 真正落地成 RCE 的最后一环，是老旧 JRE 默认允许从 LDAP/RMI/
//     COSNaming 引用的远程 codebase 加载字节码：
//       com.sun.jndi.ldap.object.trustURLCodebase
//       com.sun.jndi.rmi.object.trustURLCodebase
//       com.sun.jndi.cosnaming.object.trustURLCodebase
//     较新 JDK 已默认 false，但玩家跑旧版 MC 常用 Java 8 早期版本（默认 true）。
//     启动器统一下发 false 是纵深防御，与升级 log4j、剥离 JAVA_TOOL_OPTIONS 互补。
//
// 策略：先把命令行中所有指向这些“强制键”的 -D 赋值（无论 true/false、大小写、
// 来自启动器还是外部 JSON）全部剔除，再在 JVM 参数段末尾按规范形式追加强制值。
// 因为位于 MainClass 与所有外部参数之后，最终值一定是启动器指定的安全值，且不会
// 因重复 -D 产生歧义。纯函数、不触碰文件系统/网络，便于表驱动单测。

// enforcedJvmProperty 是一条必须由启动器拍板的 JVM 系统属性。
type enforcedJvmProperty struct {
	key   string // 规范属性名（按此大小写下发）
	value string // 强制值
}

// enforcedJvmProperties 顺序即最终追加顺序；lowerKey 为小写键，用于大小写无关匹配。
var enforcedJvmProperties = []enforcedJvmProperty{
	{"log4j2.formatMsgNoLookups", "true"},
	{"com.sun.jndi.ldap.object.trustURLCodebase", "false"},
	{"com.sun.jndi.rmi.object.trustURLCodebase", "false"},
	{"com.sun.jndi.cosnaming.object.trustURLCodebase", "false"},
}

// enforcedJvmPropertyKeys 小写键集合，判定某个 -D 是否撞上强制键。
var enforcedJvmPropertyKeys = func() map[string]struct{} {
	m := make(map[string]struct{}, len(enforcedJvmProperties))
	for _, p := range enforcedJvmProperties {
		m[lowerAscii(p.key)] = struct{}{}
	}
	return m
}()

// lowerAscii 仅折叠 A-Z（系统属性名是 ASCII 标识符，避免为这点引入 strings/toUpper
// 的 Unicode 特殊处理带来的歧义；值不参与匹配，不需要折叠）。
func lowerAscii(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

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
