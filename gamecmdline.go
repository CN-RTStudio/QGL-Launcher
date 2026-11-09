package main

import (
	"strings"
)

// gamecmdline.go —— “手工拼接的完整进程命令行”最终安全审计内核。
//
// 威胁模型：
//   launchtarget.go 审计的是“结构化”的启动计划（java/workdir/jar/classpath/...）。
//   但游戏主启动（minecraft.go）走的是另一条路：它把 javaPath 与几十个 JVM/游戏参数
//   逐个 syscall.EscapeArg 后用空格拼成一条字符串，再通过 Windows
//   STARTUPINFO 的 lpCommandLine（SysProcAttr.CmdLine）整体交给 CreateProcess，
//   exec.Command(javaPath) 本身不带 argv。也就是说，真正被系统解释的是“这条字符串”，
//   而不是某个已被逐段审计过的结构。
//
//   这条串里混入了多源数据：版本 JSON 的 JVM 参数、登录账号、外部认证服务器 URL
//   （authlib-injector 的 -javaagent:<path>=<serverURL>）、预取 base64、内存与路径等。
//   任一来源若带入 CR/LF/NUL、未配平的引号或超长段，都可能让最终命令行的分词结果
//   偏离预期（参数断裂、引号吞并后续参数）。EscapeArg 能处理普通空格与引号，但在
//   “拼装完成、交给系统前”仍应有一道独立的、针对整条命令行的最终防线，且这道防线
//   不依赖“上游每个来源都已正确转义”这一假设。
//
//   本模块只做纯判定：按 CommandLineToArgvW 的核心分词规则（双引号成组、反斜杠仅在
//   紧邻引号时特殊、空白分隔）把命令行还原成 argv，再审计长度、控制字符、引号配平、
//   参数数量/单参长度以及 argv[0]。绝不启动进程、不触碰文件系统。

const (
	// 命令行总长上限取 1 MiB：远超任何正常游戏启动（含所有库路径也到不了），只拦
	// 明显的撑爆/注入；不设会误杀正常 -D 参数长串的小上限。
	maxCommandLineBytes = 1 << 20
)

// tokenizeCommandLine 按 Windows CommandLineToArgvV 的核心规则把一条命令行还原为
// 参数切片。balanced 返回双引号是否成对（反斜杠转义掉的引号不计入）。
//
// 规则要点（与系统 CRT 分词一致的子集）：
//   - 空格/制表符在引号外作为分隔符，连续分隔符合并；
//   - 双引号进入/退出“引用态”，引用态内空白不分词；
//   - 反斜杠只在紧接双引号时特殊：2n 个反斜杠 + 引号 -> n 个反斜杠并切换/闭合引号；
//     2n+1 个反斜杠 + 引号 -> n 个反斜杠 + 一个字面引号（不切换引用态）；
//   - 其余情况下反斜杠按普通字符保留。
//
// 这里不实现 argv[0] 的特殊引号历史怪癖（程序名允许半引号），审计只需得到“引号
// 是否配平、参数边界是否清晰、argv[0] 指向什么”，保守判定更安全。
func tokenizeCommandLine(line string) (argv []string, balanced bool) {
	var (
		cur       strings.Builder
		inToken   bool
		inQuotes  bool
		pendingBs int
	)
	flush := func() {
		if inToken {
			argv = append(argv, cur.String())
			cur.Reset()
			inToken = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' {
			pendingBs++
			inToken = true
			// 反斜杠是否特殊要由“下一个字符是否引号”决定，先原样缓存到输出，
			// 遇到引号时在下面折算；非引号则保留全部反斜杠并清零计数。
			cur.WriteByte(c)
			continue
		}
		if c == '"' {
			// 把此前连续反斜杠按 CRT 规则折算：每 2 个反斜杠折叠为 1 个。
			// 折叠后多出的那个反斜杠若为奇数个，则引号被转义为字面量。
			// 先把已写入 cur 的 pendingBs 个反斜杠回退，再重写折算结果。
			if pendingBs > 0 {
				s := cur.String()
				cur.Reset()
				cur.WriteString(s[:len(s)-pendingBs])
				literalQuote := pendingBs%2 == 1
				cur.WriteString(strings.Repeat("\\", pendingBs/2))
				pendingBs = 0
				if literalQuote {
					cur.WriteByte('"')
					inToken = true
					continue
				}
				// 偶数个反斜杠：引号是结构性引号，切换引用态，不写入引号本身。
				inQuotes = !inQuotes
				inToken = true
				continue
			}
			inQuotes = !inQuotes
			inToken = true
			continue
		}
		pendingBs = 0
		if !inQuotes && (c == ' ' || c == '\t') {
			flush()
			continue
		}
		cur.WriteByte(c)
		inToken = true
	}
	flush()
	return argv, !inQuotes
}

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
