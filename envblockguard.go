package main

import (
	"sort"
	"strings"
)

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

type envRejection struct {
	Name   string
	Reason envProblem
}

func envHasByte(s string, b byte) bool { return strings.IndexByte(s, b) >= 0 }
func envHasNUL(s string) bool          { return envHasByte(s, 0) }
func envHasC0Control(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x1F || c == 0x7F {
			return true
		}
	}
	return false
}

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
