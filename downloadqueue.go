package main

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

func auditDownloadItemForEnqueue(list []DownloadItem, item DownloadItem) string {
	if len(list) >= maxDownloadListItems {
		return dqRejectFull
	}
	if !allowedDownloadItemTypes[item.ItemType] {
		return dqRejectType
	}
	if item.CustomName == "" {
		return dqRejectEmptyName
	}
	if why := auditDownloadQueueName(item.CustomName); why != dqNameRejectNone {
		return dqRejectBadName
	}
	if len(item.ID) > maxDownloadItemIDLen {
		return dqRejectIDLen
	}
	if len(item.URL) > maxDownloadItemURLLen {
		return dqRejectURLLen
	}
	if why := auditDownloadQueueURL(item.URL); why != dqURLRejectNone {
		return dqRejectBadURL
	}
	// r35：聚合字节预算——条数 / 单文件上限挡不住“合法大小 × 海量条目”的聚合放大。
	// 以队列现有声明大小之和 + 新条目声明大小判预算；size<=0 表示未知，按 0 计不影响
	// 正常下载，只有真的声称要写 1TiB 级或单条 512GiB 级才拒绝（炸磁盘才限制）。
	if why := mapByteBudgetToQueueReason(
		assessQueueByteBudget(declaredSizesFromQueue(list), item.SizeBytes).Reason,
	); why != dqRejectNone {
		return why
	}
	// 名称是落盘目录/文件名的来源，统一以名字去重，避免两个任务并发写同一目标。
	for i := range list {
		if list[i].CustomName == item.CustomName {
			return dqRejectDup
		}
	}
	return dqRejectNone
}

func describeQueueReject(why string) string {
	switch why {
	case dqRejectFull:
		return "下载队列已满，请先开始或清理现有任务"
	case dqRejectType:
		return "未知的下载任务类型"
	case dqRejectEmptyName:
		return "下载任务名称为空"
	case dqRejectIDLen:
		return "下载任务 ID 超过长度上限"
	case dqRejectURLLen:
		return "下载地址超过长度上限"
	case dqRejectBadName:
		return "下载任务名称未通过安全校验（分隔符 / 穿越段 / 保留设备名 / 结尾点）"
	case dqRejectBadURL:
		return "下载地址未通过安全校验（协议 / 用户信息 / 控制字符 / IP 直连 / 端口）"
	case dqRejectDup:
		return "已存在同名下载任务"
	case dqRejectSizeNegative:
		return "下载任务声明大小为负数，已拒绝"
	case dqRejectItemTooLarge:
		return "单个下载任务声明大小超过 " + FormatBytes(maxSingleDownloadDeclaredBytes) + " 上限"
	case dqRejectBudgetOverflow:
		return "下载队列聚合大小溢出，已拒绝"
	case dqRejectAggregateBudget:
		return "下载队列聚合大小超过 " + FormatBytes(maxDownloadBudgetBytes) + " 上限，避免写满磁盘"
	default:
		return "下载任务未通过入队校验"
	}
}
