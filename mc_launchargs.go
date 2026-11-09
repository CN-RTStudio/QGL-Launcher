package main

import (
	"strings"
)

// maxUntrustedJvmArgs 限制“版本/加载器 JSON 提供的 JVM 参数”总条数。
// 官方版本 JSON 的 JVM 参数只有十几条；Windows CreateProcess 命令行上限约
// 32K 字符，异常巨大的参数表只会来自损坏或被篡改的文件，直接截断。
const maxUntrustedJvmArgs = 256

// dangerousJvmFlagPrefixes 是不允许由外部版本 JSON 提供的 JVM 参数前缀
// （统一小写匹配）。这些参数能在 JVM 启动阶段加载任意字节码/原生库、
// 执行外部命令或替换主类，等价于任意代码执行：
//   - -javaagent / -agentlib / -agentpath：加载 JVMTI/Java agent
//   - -XX:OnError / -XX:OnOutOfMemoryError：JVM 事件触发时执行系统命令
//   - -XX:VMOptionsFile：从外部文件追加 JVM 参数，绕过本过滤
//   - -XXaltjvm(s)：替换 JVM 实现目录
//   - -Xrunjdwp/-Xrunhprof 等旧式 -Xrun 代理：开放 JDWP 远程调试即等同 RCE
//   - -jar / -m(--module)：改由攻击者指定的 jar/模块作为入口运行
//
// 启动器自身生成的 -Xmx、-Djava.library.path、-cp、--add-opens 等在过滤
// 完成之后才追加，不受影响；官方加载器使用的 -p/--module-path、--add-modules、
// --enable-native-access 不在列表中。
// 危险 JVM 参数的权威判定已抽到 jvmargs.go 的 jvmArgThreat，
// 在原 -javaagent 等前缀之外补齐了 @argfile / -noverify / 动态 agent 加载等绕过形态。

// isDangerousJvmFlag 判断单个 JVM 参数是否命中危险前缀。
// 兼容 "flag:operand"、"flag=operand" 和 "flag operand"（下一条参数）两种写法。
func isDangerousJvmFlag(lower string) bool {
	dangerous, _ := jvmArgThreat(lower)
	return dangerous
}

// filterUntrustedJvmArgs 过滤来自外部版本 JSON 的 JVM 参数。
// 返回安全参数、被拦截参数（用于日志）以及是否因超过上限而截断。
// 当危险参数以"独立 token + 下一参数为操作数"形式出现（如 -jar evil.jar），
// 操作数参数会一并丢弃。
func filterUntrustedJvmArgs(args []string) (safe []string, blocked []string, truncated bool) {
	skipOperand := false
	for i, arg := range args {
		if skipOperand {
			skipOperand = false
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(arg))
		dangerous, consumesOperand := jvmArgThreat(lower)
		if dangerous {
			blocked = append(blocked, arg)
			// 独立 token 形式时，下一条参数是其操作数（路径/命令），一并跳过。
			if consumesOperand {
				skipOperand = true
			}
			continue
		}
		safe = append(safe, arg)
		if len(safe) >= maxUntrustedJvmArgs {
			truncated = i+1 < len(args)
			break
		}
	}
	return safe, blocked, truncated
}
