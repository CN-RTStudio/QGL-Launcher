package main

// launchreport.go —— 启动总结报告内核（本地留档 / 前端"上次启动详情"）。
//
// launchsnapshot 记录"用什么启动的"（参数快照），sessionjournal 记录"何时启动、
// 何时结束、结果如何"；但两者都没有回答"这次启动到底带了哪些 JVM 参数、哪些
// 环境变量、哪些 classpath 文件"——事后排查代理被注入、log4j 标志、@argfile
// 绕过时只能靠翻原始命令，而原始命令常已轮转或被日志脱敏吞掉。
//
// 本模块在每次启动结束后从运行时输入生成一条脱敏总结：
//   - JVM 参数按类别计数（内存 / 系统属性 / 代理 / classpath / 其他），代理值只
//     留 host:port（用户名密码、查询串一律丢弃），敏感标志（-Dlog4j、@argfile）
//     单独布尔标记；
//   - 环境变量只留"被隔离的危险变量名"与计数，值绝不进报告；命名像密钥但未被
//     拦截的变量单独提示（供审计追查为何放行）；
//   - classpath 只列 jar 文件名（前 N 个），完整路径 / 盘符不进报告。
// 报告与 launchsnapshot 一样可落盘，但只含汇总计数，可安全交给前端展示。

import (
	"path/filepath"
	"strings"
	"time"
)

const (
	reportMaxJarNames   = 12
	reportMaxProxyHosts = 8
	reportMaxEnvNames   = 16
	reportMaxReportLen  = 60000
)

// JVMSummary 是 JVM 参数的去敏分类汇总。
type JVMSummary struct {
	ArgCount      int      `json:"argCount"`
	MemoryMB      int      `json:"memoryMB,omitempty"`
	SystemProps   int      `json:"systemProps"`
	ProxyHosts    []string `json:"proxyHosts,omitempty"`
	ClasspathArgs int      `json:"classpathArgs"`
	OtherArgs     int      `json:"otherArgs"`
	HasLog4jFlag  bool     `json:"hasLog4jFlag,omitempty"`
	HasArgfile    bool     `json:"hasArgfile,omitempty"`
}

// EnvSummary 是环境变量的去敏汇总。
type EnvSummary struct {
	Count          int      `json:"count"`
	BlockedNames   []string `json:"blockedNames,omitempty"`
	AllowedCount   int      `json:"allowedCount"`
	NotableSecrets int      `json:"notableSecrets"`
}

// ClasspathSummary 是 classpath 的去敏汇总。
type ClasspathSummary struct {
	JarCount int      `json:"jarCount"`
	JarNames []string `json:"jarNames,omitempty"`
	NonJar   int      `json:"nonJar"`
}

// LaunchReport 是单次启动的脱敏总结报告。
type LaunchReport struct {
	Snapshot        LaunchSnapshot    `json:"snapshot"`
	StartedAt       string            `json:"startedAt"`
	DurationMS      int64             `json:"durationMs"`
	ExitCode        int               `json:"exitCode"`
	Result          string            `json:"result"`
	JVM             JVMSummary        `json:"jvm"`
	Env             EnvSummary        `json:"env"`
	Classpath       ClasspathSummary  `json:"classpath"`
}

// jvmArgCategory 把单个 JVM 参数分成 5 类，返回值与需要留痕的"安全关注点"。
func jvmArgCategory(arg string) (cat string, memoryMB int, proxyHost string) {
	if arg == "" {
		return "other", 0, ""
	}
	if strings.HasPrefix(arg, "-Xm") {
		if v := parseMemoryMB(arg); v > 0 {
			return "memory", v, ""
		}
		return "memory", 0, ""
	}
	if strings.HasPrefix(arg, "-D") {
		kv := strings.TrimPrefix(arg, "-D")
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		lower := strings.ToLower(name)
		if strings.Contains(lower, "log4j") {
			return "log4j", 0, ""
		}
		if strings.Contains(lower, "socksproxy") || strings.Contains(lower, "httpproxy") || strings.Contains(lower, "proxyhost") {
			if i := strings.IndexByte(kv, '='); i >= 0 {
				return "proxy", 0, sanitizeProxyValue(kv[i+1:])
			}
		}
		return "sysprop", 0, ""
	}
	if strings.HasPrefix(arg, "-classpath") || strings.HasPrefix(arg, "-cp") {
		return "classpath", 0, ""
	}
	if strings.HasPrefix(arg, "@") {
		return "argfile", 0, ""
	}
	return "other", 0, ""
}

// parseMemoryMB 解析 -Xmx/-Xms 值（"512M"、"2G"），解析失败返回 0。
func parseMemoryMB(arg string) int {
	unit := ""
	num := strings.TrimPrefix(arg, "-Xm")
	if len(num) < 2 {
		return 0
	}
	flag := num[:1] // x 或 s
	num = num[1:]
	if strings.HasSuffix(num, "G") || strings.HasSuffix(num, "g") {
		unit = "G"
		num = num[:len(num)-1]
	} else if strings.HasSuffix(num, "M") || strings.HasSuffix(num, "m") {
		unit = "M"
		num = num[:len(num)-1]
	} else if strings.HasSuffix(num, "K") || strings.HasSuffix(num, "k") {
		unit = "K"
		num = num[:len(num)-1]
	}
	val := 0
	for _, c := range num {
		if c < '0' || c > '9' {
			return 0
		}
		val = val*10 + int(c-'0')
	}
	if flag != "x" && flag != "s" {
		return 0
	}
	switch unit {
	case "G":
		return val * 1024
	case "K":
		return val / 1024
	default:
		return val
	}
}

// sanitizeProxyValue 把代理值去敏为 host:port（丢弃 user:pass@ 与路径/查询串）。
func sanitizeProxyValue(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.LastIndex(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if len(v) > 512 {
		v = v[:512]
	}
	if v == "" {
		return "(empty)"
	}
	return v
}

// blockedEnvNames 是需要隔离的危险环境变量名（与 envblockguard 同口径的展示面）。
var blockedEnvNames = map[string]bool{
	"JAVA_TOOL_OPTIONS": true,
	"JDK_JAVA_OPTIONS":  true,
	"_JAVA_OPTIONS":     true,
	"JAVA_OPTS":         true,
	"CLASSPATH":         true,
	"LD_PRELOAD":        true,
	"DYLD_INSERT_LIBRARIES": true,
}

// envNameLooksSecret 判断环境变量名是否像密钥（仅命名提示，不做值判定）。
func envNameLooksSecret(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "token") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "access_key") ||
		strings.HasSuffix(lower, "_key")
}

// BuildLaunchReport 由运行时输入构建脱敏启动报告。
// jvmArgs / envNames / classpath 均为原始清单；函数只提取计数与安全关注点，
// 任何值类信息（代理凭据、token、路径）都不会进入报告字段。
func BuildLaunchReport(snapshot LaunchSnapshot, startedAt time.Time,
	jvmArgs, envNames, classpath []string, durationMS int64, exitCode int) LaunchReport {

	r := LaunchReport{
		Snapshot:   snapshot,
		StartedAt:  startedAt.Format(time.RFC3339),
		DurationMS: durationMS,
		ExitCode:   exitCode,
		Result:     launchResultOf(exitCode),
	}
	for _, a := range jvmArgs {
		cat, mem, proxy := jvmArgCategory(a)
		r.JVM.ArgCount++
		switch cat {
		case "memory":
			if mem > r.JVM.MemoryMB {
				r.JVM.MemoryMB = mem
			}
		case "sysprop":
			r.JVM.SystemProps++
		case "proxy":
			if proxy != "" && len(r.JVM.ProxyHosts) < reportMaxProxyHosts {
				r.JVM.ProxyHosts = append(r.JVM.ProxyHosts, proxy)
			}
		case "classpath":
			r.JVM.ClasspathArgs++
		case "log4j":
			r.JVM.HasLog4jFlag = true
		case "argfile":
			r.JVM.HasArgfile = true
		default:
			r.JVM.OtherArgs++
		}
	}
	for _, raw := range envNames {
		r.Env.Count++
		// 输入可能是 "NAME=VALUE"（os.Environ 格式）或纯名字；只取等号前的名字。
		name := raw
		if i := strings.IndexByte(raw, '='); i >= 0 {
			name = raw[:i]
		}
		if blockedEnvNames[name] {
			if len(r.Env.BlockedNames) < reportMaxEnvNames {
				r.Env.BlockedNames = append(r.Env.BlockedNames, name)
			}
			continue
		}
		r.Env.AllowedCount++
		if envNameLooksSecret(name) {
			r.Env.NotableSecrets++
		}
	}
	for _, cp := range classpath {
		base := filepath.Base(cp)
		if strings.HasSuffix(strings.ToLower(base), ".jar") {
			r.Classpath.JarCount++
			if len(r.Classpath.JarNames) < reportMaxJarNames {
				r.Classpath.JarNames = append(r.Classpath.JarNames, base)
			}
		} else {
			r.Classpath.NonJar++
		}
	}
	return r
}

// launchResultOf 把退出码归类为 ok / crash / nonZero。
func launchResultOf(exitCode int) string {
	switch {
	case exitCode == 0:
		return "ok"
	case exitCode < 0 || exitCode > 128:
		return "crash"
	default:
		return "nonZero"
	}
}

// ReportSize 返回报告 JSON 的估算字节数（防刷盘上限由调用方按此值截断）。
func ReportSize(r LaunchReport) int {
	return len(r.Snapshot.VersionID) + len(r.Snapshot.JavaPath) +
		len(strings.Join(r.JVM.ProxyHosts, "")) + len(strings.Join(r.Env.BlockedNames, "")) +
		len(strings.Join(r.Classpath.JarNames, "")) + 256
}
