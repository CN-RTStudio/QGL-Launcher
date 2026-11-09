package main

// auditDownloadItemForEnqueue 判断一个新条目能否进入下载队列。
// 调用方必须已经持有 downloadMutex，list 即当前队列快照。
// 返回拒绝原因码，dqRejectNone 表示允许入队。
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

// describeQueueReject 把入队拒绝原因码转成中文说明。
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
