package main

import (
	"sort"
)

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
