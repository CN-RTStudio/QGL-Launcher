package main

import (
	"strings"
)

// 背景：游戏 JVM 是 exec.Cmd 拉起的全新进程。Windows CreateProcess 接收的环境块
// 是一段 "K=V\0K=V\0...\0\0" 的 NUL 分隔结构，只要键或值里夹带一个 NUL，这一条就
// 会被拆成多条环境变量，等于能把已被 JVM 隐式参数黑名单剥离的 JAVA_TOOL_OPTIONS
// 等变量重新注入；键名首尾空白、'='、其它 C0 控制字符同样会污染或截断环境块，
// 单条变量还有长度上限。这里集中做环境块名字 / 值校验，纯函数无副作用，便于跨
// 平台单测。

const (
	envNameMaxBytes  = 255   // 环境变量名保守上限
	envValueMaxBytes = 32767 // 单条值的保守上限，给 CreateProcess 0x7FFF 限制留余量
)

type envProblem string

const (
	envProblemNone         envProblem = ""
	envProblemEmptyName    envProblem = "empty-name"
	envProblemNamePadding  envProblem = "name-whitespace-padding"
	envProblemNameEquals   envProblem = "name-contains-equals"
	envProblemNameNUL      envProblem = "name-contains-nul"
	envProblemNameControl  envProblem = "name-contains-control"
	envProblemNameTooLong  envProblem = "name-too-long"
	envProblemValueNUL     envProblem = "value-contains-nul"
	envProblemValueControl envProblem = "value-contains-control"
	envProblemValueTooLong envProblem = "value-too-long"
)

// envRejection 记录一条被拒绝的环境变量：名字 + 原因。值不落地，避免把可能含
// 令牌或敏感路径的内容写进日志结构。
type envRejection struct {
	Name   string
	Reason envProblem
}

func envHasByte(s string, b byte) bool { return strings.IndexByte(s, b) >= 0 }

func envHasNUL(s string) bool { return envHasByte(s, 0) }

// envHasC0Control 逐字节报告是否含 C0 控制字符（0x00-0x1F）或 DEL（0x7F）。
// 不按 rune 解码，因此非法 UTF-8 字节（如 0x80）不会被误判；是否非法编码与
// "是否控制字符"是两件事，环境块只关心后者。
func envHasC0Control(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x1F || c == 0x7F {
			return true
		}
	}
	return false
}

// extraEnvNameProblem 校验"启动器自己拼的 extra"键名，口径比继承环境更严格：
// 非空、首尾不允许空白、不含 '='、不含 NUL / 控制字符、不超长。
func extraEnvNameProblem(name string) envProblem {
	if len(name) == 0 {
		return envProblemEmptyName
	}
	if strings.TrimSpace(name) != name {
		return envProblemNamePadding
	}
	if envHasByte(name, '=') {
		return envProblemNameEquals
	}
	if envHasNUL(name) {
		return envProblemNameNUL
	}
	if envHasC0Control(name) {
		return envProblemNameControl
	}
	if len(name) > envNameMaxBytes {
		return envProblemNameTooLong
	}
	return envProblemNone
}

// extraEnvValueProblem 校验 extra 值：拒绝 NUL、其它 C0/DEL 控制字符与超长值。
func extraEnvValueProblem(value string) envProblem {
	if envHasNUL(value) {
		return envProblemValueNUL
	}
	if envHasC0Control(value) {
		return envProblemValueControl
	}
	if len(value) > envValueMaxBytes {
		return envProblemValueTooLong
	}
	return envProblemNone
}
