package main

// downloadqueue.go —— 下载队列入库闸。
//
// 威胁模型：
//   downloadList 是启动器在内存里维护的“待下载任务队列”，所有 AddXxxToDownloadList
//   方法都直接暴露给 Wails 前端。历史上每个入口各自做去重、各自 append，存在两类问题：
//
//   1. 资源耗尽：队列没有条数上限。前端（或被 XSS 注入的界面逻辑）可以在一个循环里
//      无限 AddToDownloadList，每次都 EventsEmit 把整条队列推回渲染层，O(n²) 的序列化
//      与内存增长最终会把启动器拖垮（每条还带 URL/版本号等字符串）。
//   2. 状态完整性：条目类型 ItemType 决定 StartDownloadList 里的分发分支（game / java /
//      mod / modpack / loader），但入库时没有任何白名单校验，畸形或未预期的类型会进入
//      队列，在真正开始下载时落到未处理分支；ID/URL 也没有长度上限，可被塞成超长串。
//
// 本内核把“能不能入队”收敛成一个纯函数，所有入口在持锁状态下统一调用：容量上限、
// 类型白名单、必填名、字段长度、同名去重。它不做任何网络/文件系统动作，便于单测。

// 队列容量上限。正常用户一次挂几十个下载任务已是上限，取 500 足以覆盖批量整合包
// 场景，同时挡住“无限塞队列”的资源耗尽；这是内存队列而非文件，上限不影响磁盘。
const maxDownloadListItems = 500

// 入队标识/地址字段的长度上限，挡住超长字符串灌入内存与事件广播。
const (
	maxDownloadItemIDLen  = 128
	maxDownloadItemURLLen = 4096
)

// 入队拒绝原因码。
const (
	dqRejectNone            = ""
	dqRejectFull            = "queue-full"                // 队列达到容量上限
	dqRejectType            = "bad-item-type"             // ItemType 不在白名单
	dqRejectEmptyName       = "empty-name"                // CustomName 为空
	dqRejectIDLen           = "id-too-long"               // ID 超长
	dqRejectURLLen          = "url-too-long"              // URL 超长
	dqRejectDup             = "duplicate-name"            // 同名条目已存在
	dqRejectSizeNegative    = "negative-size"             // 声明字节数为负
	dqRejectItemTooLarge    = "item-too-large"            // 单条声明大小超过 512GiB
	dqRejectBudgetOverflow  = "size-overflow"             // 聚合字节数溢出 int64
	dqRejectAggregateBudget = "aggregate-budget-exceeded" // 队列聚合超过 1TiB
	dqRejectBadURL          = "bad-url"                   // URL 未通过协议/主机/编码校验
	dqRejectBadName         = "bad-name"                  // 名称含分隔符/穿越段/保留设备名
)

// allowedDownloadItemTypes 是 StartDownloadList 真正能分发处理的全部类型。
// 新增下载类型时必须同时在这里登记，否则拒绝入队而不是在分发阶段静默丢失。
var allowedDownloadItemTypes = map[string]bool{
	"game":        true,
	"game+loader": true,
	"java":        true,
	"mod":         true,
	"modpack":     true,
	"loader":      true,
}
