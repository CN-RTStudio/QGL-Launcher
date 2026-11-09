package main

import "time"

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
