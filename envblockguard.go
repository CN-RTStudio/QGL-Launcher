package main

import (
	"sort"
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

// inheritedEnvProblem 用于"继承自父进程"的条目：只拒绝绝不可能合法、且能破坏
// NUL 分隔结构的情况（空键、键或值含 NUL）。其它控制字符在继承环境里可能合法
// （例如 LS_COLORS 含 ESC），这里不拦，以免误伤正常系统变量。
func inheritedEnvProblem(key, value string) envProblem {
	if len(key) == 0 {
		return envProblemEmptyName
	}
	if envHasNUL(key) {
		return envProblemNameNUL
	}
	if envHasNUL(value) {
		return envProblemValueNUL
	}
	return envProblemNone
}

// acceptExtraEnv 校验整份 extra：返回可安全下发的 map 与被拒条目列表。被拒列表
// 按 (名字, 原因) 排序，保证 map 遍历的不确定性不影响输出，方便日志与断言。
func acceptExtraEnv(extra map[string]string) (map[string]string, []envRejection) {
	accepted := make(map[string]string, len(extra))
	var rejected []envRejection
	for name, value := range extra {
		if rp := extraEnvNameProblem(name); rp != envProblemNone {
			rejected = append(rejected, envRejection{Name: name, Reason: rp})
			continue
		}
		if rp := extraEnvValueProblem(value); rp != envProblemNone {
			rejected = append(rejected, envRejection{Name: name, Reason: rp})
			continue
		}
		accepted[name] = value
	}
	sortEnvRejections(rejected)
	return accepted, rejected
}

// sanitizeInheritedEnv 清洗父进程环境条目，丢弃缺 '='、空键或键 / 值含 NUL 的脏
// 条目，原样保留其余条目（不重新编码，避免改动合法值）。
func sanitizeInheritedEnv(entries []string) (kept []string, dropped []envRejection) {
	kept = make([]string, 0, len(entries))
	for _, entry := range entries {
		key, value, ok := splitEnvironEntry(entry)
		rp := envProblemNone
		if !ok {
			rp = envProblemEmptyName
		} else {
			rp = inheritedEnvProblem(key, value)
		}
		if rp != envProblemNone {
			dropped = append(dropped, envRejection{Name: key, Reason: rp})
			continue
		}
		kept = append(kept, entry)
	}
	sortEnvRejections(dropped)
	return kept, dropped
}

func sortEnvRejections(rs []envRejection) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Name != rs[j].Name {
			return rs[i].Name < rs[j].Name
		}
		return rs[i].Reason < rs[j].Reason
	})
}

// envBlockByteSize 估算环境块字节数：每条 "K=V" 加一个分隔 NUL，整块末尾再加一个
// 终止 NUL。
func envBlockByteSize(entries []string) int {
	total := 1
	for _, e := range entries {
		total += len(e) + 1
	}
	return total
}

// envBlockWithinLimit 报告环境块是否不超过给定字节上限；limit<=0 视为不允许任何
// 内容。
func envBlockWithinLimit(entries []string, limit int) bool {
	if limit <= 0 {
		return false
	}
	return envBlockByteSize(entries) <= limit
}
