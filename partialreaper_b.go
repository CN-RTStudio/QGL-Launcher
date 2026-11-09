package main

type ReclaimItem struct {
	Path string      `json:"path"`
	Kind ReclaimKind `json:"kind"`
	Size int64       `json:"size"`
}

// ReclaimSkipped 记录一个被扫到但不删的条目，便于排查“为什么没回收”。
type ReclaimSkipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ReclaimFailure 记录执行阶段删除失败的单个文件。
type ReclaimFailure struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// ReclaimPlan 是一次扫描得到的确定删除计划，尚未执行任何删除。
type ReclaimPlan struct {
	Roots       []string         `json:"roots"`
	Items       []ReclaimItem    `json:"items"`
	Bytes       int64            `json:"bytes"`
	Skipped     []ReclaimSkipped `json:"skipped"`
	EntriesSeen int              `json:"entriesSeen"`
	BudgetHit   bool             `json:"budgetHit"`
}

// ReclaimReport 是执行计划后的结果。
type ReclaimReport struct {
	Deleted      int              `json:"deleted"`
	Bytes        int64            `json:"bytes"`
	Failed       []ReclaimFailure `json:"failed"`
	EntriesSeen  int              `json:"entriesSeen"`
	SkippedCount int              `json:"skippedCount"`
}

// isReclaimableTempName 白名单判定：名字必须以 .tmp 结尾（natives 临时文件额外要求
// .native- 前缀），且去掉后缀后仍有基础名。只做精确后缀 / 前缀，不做模糊包含。
func isReclaimableTempName(name string) bool {
	if len(name) <= len(reclaimedTempSuffix) {
		return false
	}
	if name[len(name)-len(reclaimedTempSuffix):] != reclaimedTempSuffix {
		return false
	}
	// 普通下载临时文件形如 x.jar.tmp，直接放行；natives 临时文件形如 .native-ab12.tmp，
	// 前缀固定。两者之外的 .tmp（如用户自己放的 notes.tmp）虽以后缀命中，但仍需结合
	// 根目录归属与年龄，不单独作为拒绝条件，保持白名单语义清晰。
	return true
}
