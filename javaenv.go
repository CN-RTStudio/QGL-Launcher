package main

import (
	"strings"
)

// 背景：LaunchGame 以前没有给子进程设置 cmd.Env，游戏 JVM 会完整继承启动器
// 进程的环境变量。HotSpot/OpenJDK 在启动时会自动读取若干"隐式 JVM 参数"
// 环境变量：
//
//	JAVA_TOOL_OPTIONS   （HotSpot/OpenJDK 官方支持，所有 java 启动都会追加）
//	_JAVA_OPTIONS       （Oracle JRE 旧版同样自动注入）
//	JDK_JAVA_OPTIONS    （JDK 9+ launcher 自动注入）
//	_JPI_VM_OPTIONS     （旧版 Java Plug-in / 部分捆绑 JRE 使用）
//	IBM_JAVA_OPTIONS    （IBM Semeru / J9 运行时）
//
// 攻击者（或被篡改的系统环境、别的恶意程序）只要把这些变量设成
// "-javaagent:\\evil\x.jar" / "-agentpath:..."，就能在我们对版本 JSON /
// JVM 参数做的危险参数过滤之外注入任意 javaagent 与本地代理——等于前面那一整
// 层 -javaagent 白名单形同虚设。CLASSPATH 同理：环境里的 CLASSPATH 会排在
// 命令行 -cp 之前参与类解析，可被用来顶替 Minecraft / authlib 的类。
//
// 启动游戏是"拉起一个全新 JVM"而不是"在本进程内执行受信代码"，因此正确做法
// 是给子进程一份净化过的环境：系统运行必需的变量照旧透传，只剥掉这几个会被
// JVM 隐式解释成参数 / 类路径的变量。
var jvmOptionEnvBlocklist = map[string]struct{}{
	"JAVA_TOOL_OPTIONS":   {},
	"_JAVA_OPTIONS":       {},
	"JDK_JAVA_OPTIONS":    {},
	"_JPI_VM_OPTIONS":     {},
	"IBM_JAVA_OPTIONS":    {},
	"JAVA_VM_OPTIONS":     {},
	"OPENJ9_JAVA_OPTIONS": {}, // Eclipse OpenJ9 / IBM Semeru：等价于 JAVA_TOOL_OPTIONS 的隐式注入变量
	"CLASSPATH":           {},
}

// splitEnvironEntry 解析 "KEY=VALUE" 形式的环境变量条目。
// Windows 允许变量名中出现等号以外的字符（形如 "=C:=C:\..." 的 drive-cwd
// 变量除外，那种条目以 '=' 开头，这里原样保留为 key="" 由调用方决定去留）。
func splitEnvironEntry(entry string) (key, value string, ok bool) {
	idx := strings.IndexByte(entry, '=')
	if idx < 0 {
		return "", "", false
	}
	return entry[:idx], entry[idx+1:], true
}

// isJVMInjectionEnv 判断某个环境变量名是否属于"会被 JVM 隐式当作启动参数 /
// 类路径加载"的变量。比较按大小写不敏感处理：Windows 环境变量大小写不敏感，
// 写成 java_tool_options 一样会被读到。
func isJVMInjectionEnv(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	_, blocked := jvmOptionEnvBlocklist[upper]
	return blocked
}

// buildGameEnvironment 构造传给游戏 JVM 子进程的环境变量列表（"KEY=VALUE"）。
//
//	parent ：通常传 os.Environ()；抽成参数是为了测试可重复、不依赖真实机器。
//	extra  ：需要额外注入 / 覆盖的变量（如启动器想显式给 JAVA_HOME 等），
//	         同名键最终以 extra 为准；nil 合法。
//	stripped：不为 nil 时收集被剥掉的变量名（大小写归一后的名字），用于日志，
//	         不记录值——这些值可能包含敏感路径或令牌。
//
// 规则：
//  1. 非 "K=V" 形式的脏条目直接丢弃；
//  2. 命中 JVM 隐式参数 / CLASSPATH 黑名单的条目剥掉并登记；
//  3. 其余条目原样透传，重复键保留最后一个（与 Windows 进程环境语义一致）；
//  4. extra 最后覆盖合并。
func buildGameEnvironment(parent []string, extra map[string]string, stripped *[]string) []string {
	return buildGameEnvironmentAudited(parent, extra, stripped, nil)
}
