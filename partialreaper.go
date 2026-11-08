package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

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

// isNativeTempName 区分 natives 解压临时文件（.native-*.tmp）。
func isNativeTempName(name string) bool {
	return isReclaimableTempName(name) && name[:len(reclaimedNativePrefix)] == reclaimedNativePrefix
}

// reclaimCandidateInput 是纯判定函数的输入，把文件系统细节隔离在外便于单测。
type reclaimCandidateInput struct {
	Name       string
	WithinRoot bool   // 已解析符号链接后是否仍严格位于根目录内
	IsSymlink  bool   // 该条目或其任一祖先是否为符号链接
	IsRegular  bool   // 是否普通文件
	Mtime      time.Time
	Size       int64
	BaseExists bool   // 仅对 .qglmeta：同目录基础文件是否存在
	Now        time.Time
}

// decideReclaimCandidate 是不碰文件系统的纯判定：返回（是否纳入, 类型, 跳过原因）。
// 三个返回值约定：纳入时 kind 有效、reason 为空；否则 ok=false、kind=""、reason 给码。
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

// assessReclaimBudget 在纳入一个候选前判断数量 / 字节预算是否还允许。
// 传入当前计划计数，返回是否允许纳入以及命中后是否恰好到顶。
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
func pathResolvesWithinRoot(root, target string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	if real, err := filepath.EvalSymlinks(targetAbs); err == nil {
		targetAbs = real
	}
	if real, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = real
	}
	if targetAbs == rootAbs {
		return true
	}
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	return rel != ".." && !startsWithParentSegment(rel)
}

// startsWithParentSegment 判断相对路径是否以 "../" 开头（逃逸根目录）。
func startsWithParentSegment(rel string) bool {
	return len(rel) >= 3 && rel[0] == '.' && rel[1] == '.' && rel[2] == '/'
}

// planReclaimRoot 扫描单个根目录，把满足全部条件的残留文件纳入计划。
// 递归受深度 / 条目预算限制；任何符号链接目录不下钻，避免被引出根或陷入链接环。
func planReclaimRoot(root string, now time.Time, plan *ReclaimPlan) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: root, Reason: reclaimSkipNotInRoot})
		return
	}
	if info, statErr := os.Stat(rootAbs); statErr != nil || info == nil {
		// 根目录不存在视为“没有可回收内容”，不算错误。
		return
	}

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > reclaimerMaxDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			plan.EntriesSeen++
			if plan.EntriesSeen > reclaimerMaxEntries {
				plan.BudgetHit = true
				return
			}
			full := filepath.Join(dir, entry.Name())

			// 符号链接（无论文件还是目录）一律不下钻、不删除：回收器永远不跟随链接。
			if entry.Type()&fs.ModeSymlink != 0 {
				plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: full, Reason: reclaimSkipSymlink})
				continue
			}
			if entry.IsDir() {
				if !pathResolvesWithinRoot(rootAbs, full) {
					plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: full, Reason: reclaimSkipNotInRoot})
					continue
				}
				walk(full, depth+1)
				continue
			}

			info, infoErr := entry.Info()
			in := reclaimCandidateInput{
				Name:       entry.Name(),
				WithinRoot: pathResolvesWithinRoot(rootAbs, full),
				IsSymlink:  false, // 已在上面拦截符号链接
				Now:        now,
			}
			if infoErr == nil && info != nil {
				in.IsRegular = info.Mode().IsRegular()
				in.Mtime = info.ModTime()
				in.Size = info.Size()
			}
			// 侧车需要“同目录基础文件是否存在”这一输入。
			if base, ok := isReclaimableMetaName(entry.Name()); ok {
				if _, bErr := os.Lstat(filepath.Join(dir, base)); bErr == nil {
					in.BaseExists = true
				}
			}

			ok, kind, reason := decideReclaimCandidate(in)
			if !ok {
				plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: full, Reason: reason})
				continue
			}
			if !assessReclaimBudget(len(plan.Items), plan.Bytes, in.Size, reclaimerMaxBytes) {
				plan.BudgetHit = true
				plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: full, Reason: reclaimSkipBudget})
				return
			}
			plan.Items = append(plan.Items, ReclaimItem{Path: full, Kind: kind, Size: in.Size})
			plan.Bytes += in.Size
		}
	}
	walk(rootAbs, 0)
}

// BuildReclaimPlan 对一组根目录生成统一回收计划。根目录由调用方显式给出（只允许
// 传启动器自有的缓存 / 数据目录），回收器自己不猜测磁盘路径。
func BuildReclaimPlan(roots []string, now time.Time) ReclaimPlan {
	plan := ReclaimPlan{Roots: append([]string(nil), roots...)}
	for _, root := range roots {
		if plan.EntriesSeen > reclaimerMaxEntries || len(plan.Items) >= reclaimerMaxFiles ||
			plan.Bytes >= reclaimerMaxBytes {
			plan.BudgetHit = true
			break
		}
		planReclaimRoot(root, now, &plan)
	}
	return plan
}

// executeReclaimPlan 严格按计划点名删除，不重新判定、不扩展范围。删除失败只记录，
// 不中断后续条目。执行者必须确认计划来自 BuildReclaimPlan，而非外部传入。
func executeReclaimPlan(plan ReclaimPlan) ReclaimReport {
	report := ReclaimReport{
		EntriesSeen:  plan.EntriesSeen,
		SkippedCount: len(plan.Skipped),
	}
	for _, item := range plan.Items {
		// 最后一道归属闸：即便计划被异常构造，执行前再次确认文件在某个允许根内。
		within := false
		for _, root := range plan.Roots {
			if pathResolvesWithinRoot(root, item.Path) {
				within = true
				break
			}
		}
		if !within {
			report.Failed = append(report.Failed, ReclaimFailure{Path: item.Path, Error: reclaimSkipNotInRoot})
			continue
		}
		// 用 Lstat 而非 Remove 直接删：拒绝任何符号链接 / 目录，只删普通文件。
		info, err := os.Lstat(item.Path)
		if err != nil {
			continue // 文件已不存在等同回收完成，不计失败
		}
		if info.Mode()&fs.ModeSymlink != 0 || info.IsDir() {
			report.Failed = append(report.Failed, ReclaimFailure{Path: item.Path, Error: reclaimSkipIrregular})
			continue
		}
		if err := os.Remove(item.Path); err != nil {
			report.Failed = append(report.Failed, ReclaimFailure{Path: item.Path, Error: err.Error()})
			continue
		}
		report.Deleted++
		report.Bytes += item.Size
	}
	return report
}
