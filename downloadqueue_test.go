package main

import "testing"

func baseQueueItem() DownloadItem {
	return DownloadItem{
		ID:         "1.20.1",
		URL:        "https://example.test/1.20.1.json",
		CustomName: "1.20.1",
		Type:       "release",
		ItemType:   "game",
		Status:     "pending",
	}
}

func TestAuditDownloadItemAccepts(t *testing.T) {
	item := baseQueueItem()
	if why := auditDownloadItemForEnqueue(nil, item); why != dqRejectNone {
		t.Fatalf("合法条目应放行, got %s", why)
	}
	for _, ty := range []string{"game", "game+loader", "java", "mod", "modpack", "loader"} {
		it := baseQueueItem()
		it.ItemType = ty
		it.CustomName = "name-" + ty
		if why := auditDownloadItemForEnqueue(nil, it); why != dqRejectNone {
			t.Errorf("类型 %q 应放行, got %s", ty, why)
		}
	}
}

func TestAuditDownloadItemRejects(t *testing.T) {
	if why := auditDownloadItemForEnqueue(nil, DownloadItem{ItemType: "game"}); why != dqRejectEmptyName {
		t.Errorf("空名称应被拒, got %q", why)
	}
	badType := baseQueueItem()
	badType.ItemType = "exec-shell"
	if why := auditDownloadItemForEnqueue(nil, badType); why != dqRejectType {
		t.Errorf("未知类型应被拒, got %q", why)
	}
	longID := baseQueueItem()
	longID.ID = string(make([]byte, maxDownloadItemIDLen+1))
	if why := auditDownloadItemForEnqueue(nil, longID); why != dqRejectIDLen {
		t.Errorf("超长 ID 应被拒, got %q", why)
	}
	longURL := baseQueueItem()
	longURL.URL = string(make([]byte, maxDownloadItemURLLen+1))
	if why := auditDownloadItemForEnqueue(nil, longURL); why != dqRejectURLLen {
		t.Errorf("超长 URL 应被拒, got %q", why)
	}
}

func TestAuditDownloadItemDuplicate(t *testing.T) {
	existing := baseQueueItem()
	list := []DownloadItem{existing}
	dup := baseQueueItem()
	if why := auditDownloadItemForEnqueue(list, dup); why != dqRejectDup {
		t.Fatalf("同名条目应判重, got %q", why)
	}
	other := baseQueueItem()
	other.CustomName = "1.20.1-fabric"
	if why := auditDownloadItemForEnqueue(list, other); why != dqRejectNone {
		t.Fatalf("不同名条目应放行, got %q", why)
	}
}

func TestAuditDownloadItemCapacity(t *testing.T) {
	list := make([]DownloadItem, maxDownloadListItems)
	for i := range list {
		list[i] = DownloadItem{
			ID:         "uniq-" + itoaTest(i),
			CustomName: "uniq-" + itoaTest(i),
			ItemType:   "game",
		}
	}
	fresh := baseQueueItem()
	fresh.CustomName = "definitely-not-present"
	if why := auditDownloadItemForEnqueue(list, fresh); why != dqRejectFull {
		t.Fatalf("队列达到上限应拒绝入队, got %q", why)
	}
	// 少一条时应允许（即使名字不冲突也只受容量闸控制）。
	if why := auditDownloadItemForEnqueue(list[:len(list)-1], fresh); why != dqRejectNone {
		t.Fatalf("未满队列应允许新唯一条目, got %q", why)
	}
}

func TestDescribeQueueReject(t *testing.T) {
	for _, code := range []string{
		dqRejectFull, dqRejectType, dqRejectEmptyName, dqRejectIDLen, dqRejectURLLen, dqRejectDup,
	} {
		if describeQueueReject(code) == "" {
			t.Errorf("原因码 %s 缺少中文说明", code)
		}
	}
	if describeQueueReject("nope") == "" {
		t.Fatal("未知原因码应有兜底说明")
	}
}

// itoaTest 用最简单的十进制转换生成唯一名，避免在测试里再引入 strconv 之外的依赖风格。
func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
