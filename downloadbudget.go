package main

// downloadbudget.go —— 下载队列“聚合字节预算”纯逻辑内核。
//
// 威胁模型：
//   downloadqueue.go 已限制队列条数（500）与字段长度，但没有限制“这 500 条加起来
//   一共要往磁盘写多少字节”。一个被 XSS 注入 / 被恶意整合包清单控制的前端，可以让
//   每条任务都声称自己是超大文件（Modrinth 的 files[].size 由远端 JSON 给），500 条
//   聚合后是天文数字，真跑起来会把盘写到耗尽。单文件大小校验只看“每一条”，挡不住
//   “合法大小 × 海量条数”的聚合放大。
//
//   本内核只做纯函数：给定队列里已知大小的条目与新条目声明大小，裁决聚合预算。
//   约定 size<=0 表示“服务端未声明大小”，按 0 计（不能因没有 Content-Length 就拒绝
//   正常下载）；阈值故意取得极宽——单条 512GiB、队列聚合 1TiB——正常游戏 / 整合包
//   绝不会触线，只有真的会把磁盘灌爆时才拦，符合“炸磁盘才限制”。
//
//   它与 diskspaceguard 的分工：budget 只看“声明字节数的算术”，不碰文件系统；
//   是否真的超磁盘剩余，由 diskspaceguard 结合平台探测决定。

const (
	// maxSingleDownloadDeclaredBytes 单条任务声明大小上限（512GiB），
	// 与下载哈希可处理上限 MAX_HASHABLE_DOWNLOAD_BYTES 同量级，拦“单条天文数字”。
	maxSingleDownloadDeclaredBytes int64 = 512 << 30
	// maxDownloadBudgetBytes 整个下载队列“已知大小”的聚合上限（1TiB）。
	// 只有聚合声称要写超过 1TiB 才拒绝，正常批量下载远到不了这里。
	maxDownloadBudgetBytes int64 = 1 << 40
)

// 字节预算拒绝原因码。
type byteBudgetReason string

const (
	byteBudgetOK           byteBudgetReason = ""
	byteBudgetNegative     byteBudgetReason = "negative-size"             // 声明了负大小
	byteBudgetOversizeItem byteBudgetReason = "item-too-large"            // 单条超过 512GiB
	byteBudgetOverflow     byteBudgetReason = "size-overflow"             // 聚合求和溢出 int64
	byteBudgetOverBudget   byteBudgetReason = "aggregate-budget-exceeded" // 聚合超过 1TiB
)

// ByteBudgetDecision 是一次聚合预算裁决。
type ByteBudgetDecision struct {
	OK        bool
	Reason    byteBudgetReason
	Existing  int64 // 队列中已知大小之和（size<=0 的未知项按 0）
	Incoming  int64 // 新条目声明大小（<=0 视为未知 0）
	Projected int64 // Existing+Incoming（OK / over-budget 时有效）
	Limit     int64 // 聚合上限
	Headroom  int64 // 距上限还剩多少（over-budget 时为负，表示超出量）
}

// normalizeDeclaredSize 把新条目的声明大小归一化：负数是非法（不是“未知”），
// 0 / 正数原样；未知只能用 0 表达，不允许用负值。
func normalizeDeclaredSize(size int64) (int64, bool) {
	if size < 0 {
		return 0, false
	}
	return size, true
}
