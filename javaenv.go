package main

import (
	"os"
	"os/exec"
	"strconv"
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

// buildGameEnvironmentAudited 在 buildGameEnvironment 基础上额外收集“因键 / 值
// 非法（NUL、控制字符、空白填充、超长等）而被拒绝”的条目，供启动入口记日志与
// 安全审计。rejected 传 nil 时行为与 buildGameEnvironment 完全一致。
func buildGameEnvironmentAudited(parent []string, extra map[string]string, stripped *[]string, rejected *[]envRejection) []string {
	index := make(map[string]int) // 归一化大写名 -> env 切片下标
	env := make([]string, 0, len(parent)+len(extra))

	// 先清洗继承环境：丢弃缺 '='、空键、键 / 值含 NUL 的脏条目，避免它们破坏
	// CreateProcess 的 NUL 分隔环境块。
	cleanParent, dropped := sanitizeInheritedEnv(parent)
	if rejected != nil {
		*rejected = append(*rejected, dropped...)
	}

	for _, entry := range cleanParent {
		key, value, _ := splitEnvironEntry(entry)
		if isJVMInjectionEnv(key) {
			if stripped != nil {
				*stripped = append(*stripped, strings.ToUpper(strings.TrimSpace(key)))
			}
			continue
		}
		upper := strings.ToUpper(key)
		if pos, exists := index[upper]; exists {
			env[pos] = key + "=" + value
			continue
		}
		index[upper] = len(env)
		env = append(env, key+"="+value)
	}

	// extra 是启动器自己拼的输入，口径更严格：键首尾空白、'='、NUL / 控制字符、
	// 超长一律拒绝，值同样不允许 NUL / 控制字符 / 超长。
	accepted, extraRejected := acceptExtraEnv(extra)
	if rejected != nil {
		*rejected = append(*rejected, extraRejected...)
	}

	for key, value := range accepted {
		upper := strings.ToUpper(key)
		if pos, exists := index[upper]; exists {
			env[pos] = key + "=" + value
			continue
		}
		index[upper] = len(env)
		env = append(env, key+"="+value)
	}

	return env
}

// currentGameEnvironment 是实际启动游戏时调用的便捷封装：读取当前进程环境，
// 剥掉 JVM 注入变量，返回可直接赋给 cmd.Env 的列表与被剥掉的变量名。
func currentGameEnvironment(extra map[string]string) ([]string, []string) {
	var stripped []string
	env := buildGameEnvironment(os.Environ(), extra, &stripped)
	return env, stripped
}

// applySanitizedJVMEnv 给任意一个“即将拉起外部 java 进程”的 cmd 下发净化后的
// 环境，并对被剥掉的隐式 JVM 参数变量做日志与安全审计留痕。
//
// 历史上只有 LaunchGame 做了环境净化，而 Forge / OptiFine / 第三方 jar 安装器 /
// 内置服务端这几个入口要么不设 cmd.Env（Go 默认继承整个父进程环境），要么直接
// append(os.Environ(), ...)，导致 JAVA_TOOL_OPTIONS 一族注入在这些 JVM 上全部
// 复活。所有 java 子进程必须统一走这里，不允许再手写 cmd.Env。
//
//	source ：仅用于日志 / 审计，标识是哪条启动链（如 "ForgeInstaller"）。
//	extra  ：需要显式覆盖给子进程的变量（如 OptiFine 安装器需要的 APPDATA）。
func (a *App) applySanitizedJVMEnv(cmd *exec.Cmd, source string, extra map[string]string) {
	var stripped []string
	var rejected []envRejection
	env := buildGameEnvironmentAudited(os.Environ(), extra, &stripped, &rejected)
	cmd.Env = env
	for _, name := range stripped {
		a.writeLog("安全: 已从%s进程环境中剥离隐式 JVM 参数变量: %s", source, name)
	}
	if len(stripped) > 0 {
		// 只记录变量名（值可能含敏感路径/令牌），作为“环境被人动过”的留痕。
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityWarn, auditActionStripped,
			source, source+" 启动时剥离隐式 JVM 参数环境变量: "+strings.Join(stripped, ","))
	}
	for _, rj := range rejected {
		// 同样只记录变量名与拒绝原因，绝不记录值。
		a.writeLog("安全: %s启动环境变量 %q 因非法被拒: %s", source, rj.Name, string(rj.Reason))
	}
	if len(rejected) > 0 {
		names := make([]string, 0, len(rejected))
		for _, rj := range rejected {
			names = append(names, rj.Name+"("+string(rj.Reason)+")")
		}
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityWarn, auditActionRejected,
			source, source+" 启动时拒绝非法环境变量: "+strings.Join(names, ","))
	}

	// CreateProcess 命令行有 32767 字符上限；超长时系统调用会以晦涩错误失败。
	// 这里在 spawn 前给出确定的诊断留痕（classpath 通常就是最长参数）。
	if cmd != nil {
		report := argvLengthReportFor(cmd.Args)
		if report.Over {
			longest := ""
			if report.Longest >= 0 && report.Longest < len(cmd.Args) {
				longest = cmd.Args[report.Longest]
				if len(longest) > 160 {
					longest = longest[:160] + "..."
				}
			}
			a.writeLog("安全: %s命令行长度 %d 超过 CreateProcess 上限 %d，最长参数: %s",
				source, report.Chars, report.Limit, longest)
			recordSecurityEvent(auditCategoryLaunch, auditSeverityWarn, auditActionDetected,
				source, source+" 命令行超过 CreateProcess 长度上限: "+strconv.Itoa(report.Chars)+
					"/"+strconv.Itoa(report.Limit))
		}
	}
}
