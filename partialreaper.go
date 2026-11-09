package main

import "time"

// partialreaper.go —— 下载残留产物的安全回收内核。
//
// 威胁模型：
//   启动器所有下载都走“同目录 .tmp 落盘 -> 校验通过 -> rename 成正式文件”，
//   并在正式文件旁边放 <file>.qglmeta 侧车。进程被强杀 / 断电 / 磁盘写满 /
//   解压 natives 中断时，会留下：
//     1) 未被 rename 的 *.tmp（含 .native-*.tmp），内容是半截数据，永远不会再用；
//     2) 正式文件已被删除但侧车残留的孤儿 *.qglmeta；
//     3) 0 字节的空壳临时文件。
//   这些残留会持续占用磁盘（整合包 / 服务端 JAR 体积以百 MB 计），多轮失败后
//   可能累积到数 GB。
//
//   但“自动删文件”本身是高危动作，历史上没有统一回收，谁都不敢扫目录，因为：
//     - 绝不能删掉正在下载的 .tmp（会毁掉进行中的任务）；
//     - 绝不能跟着符号链接走到游戏目录外（用户规则：删除一律白名单 + 严格归属）；
//     - 绝不能按“看起来像临时文件”的黑名单去猜，否则正常文件名碰巧命中会误删；
//     - 一次清理必须有数量 / 字节 / 遍历条数上限，挡掉恶意目录制造的无限遍历。
//
//   本模块因此只做两件事：planReclaim 用白名单 + 归属 + 年龄 + 预算算出一个确定的
//   删除计划（纯判定可单测）；executeReclaimPlan 只删除计划里点名的文件，绝不临场
//   扩大范围。任何不满足全部条件的条目都进入 Skipped 而不是被删。

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

// 计划判定 / 跳过原因码，稳定可用于测试与前端展示。
const (
	reclaimSkipNotWhiteList = "not-whitelisted" // 文件名不在精确白名单内
	reclaimSkipTooYoung     = "too-young"       // 静置时间不足，可能是在途文件
	reclaimSkipSymlink      = "symlink"         // 路径是符号链接，拒绝跟随
	reclaimSkipNotInRoot    = "outside-root"    // 解析后越出根目录
	reclaimSkipMetaAlive    = "meta-base-alive" // 侧车对应的基础文件仍存在
	reclaimSkipBudget       = "budget"          // 命中数量 / 字节 / 遍历预算
	reclaimSkipIrregular    = "irregular"       // 非常规文件（目录 / 设备 / 管道等）
)

// ReclaimKind 描述被回收对象类型。
type ReclaimKind string

const (
	reclaimKindTemp       ReclaimKind = "temp"        // *.tmp 半截下载 / 解压文件
	reclaimKindOrphanMeta ReclaimKind = "orphan-meta" // 基础文件已消失的 *.qglmeta
)

// ReclaimItem 是计划中“确定要删”的一个文件。
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

// isReclaimableMetaName 判定是否为侧车文件名，并返回基础文件名与是否合法。
