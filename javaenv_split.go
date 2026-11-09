package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

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
