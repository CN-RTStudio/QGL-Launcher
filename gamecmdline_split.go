package main

import (
	"strings"
)

// AuditCommandLine 对一条“即将整体交给 CreateCommandLine”的完整命令行做最终审计，
// 返回还原出的 argv 与审计结论。javaExeRequired 为真时额外校验 argv[0] 必须是安全的
// java 可执行（绝对、非 UNC、无穿越、平台扩展名正确）。
func AuditCommandLine(line string, javaExeRequired bool) ([]string, *LaunchAudit) {
	a := &LaunchAudit{}
	add := func(code, severity, detail string) {
		a.Findings = append(a.Findings, LaunchFinding{
			Code: code, Severity: severity, Field: "commandLine", Detail: detail,
		})
		a.tallyOne(severity)
	}

	if strings.TrimSpace(line) == "" {
		add("cmdline-empty", launchSeverityCritical, "命令行为空")
		a.tally()
		return nil, a
	}
	if len(line) > maxCommandLineBytes {
		add("cmdline-long", launchSeverityCritical, "命令行总长度超过上限")
	}
	// NUL/CR/LF 绝不能出现在将被整体解释的命令行里；其余可打印控制符（制表符是
	// 合法分隔符）之外的 ASCII 控制字符同样拒绝。
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == 0x00 || c == '\r' || c == '\n' {
			add("cmdline-newline-nul", launchSeverityCritical, "命令行含 CR/LF/NUL 注入字符")
			break
		}
		if c < 0x20 && c != '\t' {
			add("cmdline-control", launchSeverityCritical, "命令行含 ASCII 控制字符")
			break
		}
	}

	argv, balanced := tokenizeCommandLine(line)
	if !balanced {
		add("cmdline-unbalanced-quote", launchSeverityCritical, "命令行双引号未配平")
	}
	if len(argv) == 0 {
		add("cmdline-no-argv", launchSeverityCritical, "命令行解析不出任何参数")
	}
	if len(argv) > maxLaunchArgs {
		add("cmdline-too-many-args", launchSeverityCritical, "命令行参数数量过多")
	}
	for i, arg := range argv {
		if len(arg) > maxLaunchArgBytes {
			add("cmdline-arg-long", launchSeverityCritical, "单个命令行参数过长")
			break
		}
		if strings.ContainsRune(arg, 0x00) {
			add("cmdline-arg-nul", launchSeverityCritical, "参数中含 NUL")
			break
		}
		_ = i
	}
	if javaExeRequired && len(argv) > 0 {
		// argv[0] 是程序名；分词已剥离结构性引号，若仍残留引号说明形态异常。
		exe := argv[0]
		if strings.ContainsAny(exe, "\"") {
			add("cmdline-argv0-quote", launchSeverityCritical, "程序名含未被正确转义的引号")
		} else {
			a.Findings = append(a.Findings, auditJavaExe(exe)...)
			a.tally()
		}
	}
	a.tally()
	return argv, a
}
