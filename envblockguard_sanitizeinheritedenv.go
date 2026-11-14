package main

import (
	"sort"
)

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
