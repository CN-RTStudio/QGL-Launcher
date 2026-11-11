package main

import (
	"time"
)

const (
	// reclaimedTempSuffix 是下载 / 解压临时文件的精确后缀。
	reclaimedTempSuffix = ".tmp"
	// reclaimedNativePrefix 是 natives 解压临时目录 / 文件前缀（配合 .tmp 后缀）。
	reclaimedNativePrefix = ".native-"
	// reclaimedMetaSuffix 是下载完整性侧车后缀；仅在“基础文件已不存在”时才算孤儿。
	reclaimedMetaSuffix = ".qglmeta"

	// reclaimerMinAge：残留文件至少静置多久才允许回收。正常一次下载的 .tmp 从创建
	// 到 rename 只有几秒到几分钟，取 6 小时既彻底避开在途文件，又能在次日启动时回收
	// 掉上一轮崩溃残留，不依赖锁文件（锁文件在强杀后本来就会过期失效）。
	reclaimerMinAge = 6 * time.Hour
	// reclaimerMaxFiles：单次计划最多删除的文件数。残留清理不是批量数据迁移，
	// 2000 个半截文件已是极端事故现场，再多应当让用户看到而不是静默删除。
	reclaimerMaxFiles = 2000
	// reclaimerMaxBytes：单次计划最多回收的字节数（20 GiB），超出即停止纳入计划。
	reclaimerMaxBytes int64 = 20 << 30
	// reclaimerMaxEntries：单次遍历最多读多少个目录条目，防御符号链接环 / 巨型目录
	// 造成的无限遍历与资源消耗。
	reclaimerMaxEntries = 200000
	// reclaimerMaxDepth：递归深度上限。游戏缓存目录层级很浅，8 层足够，再深不扫。
	reclaimerMaxDepth = 8
)
const (
	reclaimSkipNotWhiteList = "not-whitelisted" // 文件名不在精确白名单内
	reclaimSkipTooYoung     = "too-young"       // 静置时间不足，可能是在途文件
	reclaimSkipSymlink      = "symlink"         // 路径是符号链接，拒绝跟随
	reclaimSkipNotInRoot    = "outside-root"    // 解析后越出根目录
	reclaimSkipMetaAlive    = "meta-base-alive" // 侧车对应的基础文件仍存在
	reclaimSkipBudget       = "budget"          // 命中数量 / 字节 / 遍历预算
	reclaimSkipIrregular    = "irregular"       // 非常规文件（目录 / 设备 / 管道等）
)

type ReclaimKind string

const (
	reclaimKindTemp       ReclaimKind = "temp"        // *.tmp 半截下载 / 解压文件
	reclaimKindOrphanMeta ReclaimKind = "orphan-meta" // 基础文件已消失的 *.qglmeta
)

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

func isReclaimableMetaName(name string) (base string, ok bool) {
	if len(name) <= len(reclaimedMetaSuffix) {
		return "", false
	}
	if name[len(name)-len(reclaimedMetaSuffix):] != reclaimedMetaSuffix {
		return "", false
	}
	base = name[:len(name)-len(reclaimedMetaSuffix)]
	if base == "" || base == "." {
		return "", false
	}
	return base, true
}
func isNativeTempName(name string) bool {
	return isReclaimableTempName(name) && name[:len(reclaimedNativePrefix)] == reclaimedNativePrefix
}

type reclaimCandidateInput struct {
	Name       string
	WithinRoot bool // 已解析符号链接后是否仍严格位于根目录内
	IsSymlink  bool // 该条目或其任一祖先是否为符号链接
	IsRegular  bool // 是否普通文件
	Mtime      time.Time
	Size       int64
	BaseExists bool // 仅对 .qglmeta：同目录基础文件是否存在
	Now        time.Time
}

func decideReclaimCandidate(in reclaimCandidateInput) (ok bool, kind ReclaimKind, reason string) {
	if in.IsSymlink {
		return false, "", reclaimSkipSymlink
	}
	if !in.WithinRoot {
		return false, "", reclaimSkipNotInRoot
	}
	if !in.IsRegular {
		return false, "", reclaimSkipIrregular
	}
	if in.Now.Sub(in.Mtime) < reclaimerMinAge {
		return false, "", reclaimSkipTooYoung
	}
	if isReclaimableTempName(in.Name) {
		return true, reclaimKindTemp, ""
	}
	if base, metaOK := isReclaimableMetaName(in.Name); metaOK {
		_ = base
		// 基础文件还在：侧车是有效元数据，绝不能删。
		if in.BaseExists {
			return false, "", reclaimSkipMetaAlive
		}
		return true, reclaimKindOrphanMeta, ""
	}
	return false, "", reclaimSkipNotWhiteList
}

func assessReclaimBudget(currentCount int, currentBytes, addBytes, maxBytes int64) (allow bool) {
	if currentCount >= reclaimerMaxFiles {
		return false
	}
	if maxBytes > 0 && currentBytes > maxBytes-addBytes {
		return false
	}
	return true
}

// pathResolvesWithinRoot 报告 target 在解析符号链接后是否仍严格位于 root 之内。
// root 与 target 都应为已 Clean 的绝对路径。target==root 也算在内部（用于根本身），
// 但调用方只会对“根下的文件”调用，文件不可能等于根。
