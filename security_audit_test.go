package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestAudit(clock func() time.Time) *securityAudit {
	a := newSecurityAudit()
	if clock != nil {
		a.now = clock
	}
	return a
}

func TestSanitizeAuditDetail(t *testing.T) {
	// 邮箱 / token / 内网 IP 必须被打码。
	in := "token=abcdef0123456789ABCDEF from user@example.com at 192.168.1.42"
	out := sanitizeAuditDetail(in)
	if strings.Contains(out, "abcdef0123456789ABCDEF") {
		t.Fatalf("token 未脱敏: %s", out)
	}
	if strings.Contains(out, "user@example.com") {
		t.Fatalf("邮箱未脱敏: %s", out)
	}
	if strings.Contains(out, "192.168.1.42") {
		t.Fatalf("内网 IP 未脱敏: %s", out)
	}

	// 控制字符被替换成空格。
	if got := sanitizeAuditDetail("a\x00b\nc"); strings.ContainsRune(got, 0) {
		t.Fatalf("NUL 未清理: %q", got)
	}

	// 超长 detail 被截断并加省略号。
	long := strings.Repeat("路", auditMaxDetailRunes+120)
	got := sanitizeAuditDetail(long)
	if n := len([]rune(got)); n != auditMaxDetailRunes+1 {
		t.Fatalf("detail 限长错误: got %d runes", n)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("超长 detail 应以省略号结尾: %q", got)
	}
}

func TestAuditValidators(t *testing.T) {
	if !validAuditCategory(auditCategoryZip) {
		t.Fatal("内置类别应合法")
	}
	if validAuditCategory("dropping-tables") {
		t.Fatal("未知类别不应合法")
	}
	for _, v := range []string{auditSeverityInfo, auditSeverityWarn, auditSeverityCritical} {
		if !validAuditSeverity(v) {
			t.Fatalf("严重级别 %q 应合法", v)
		}
	}
	if validAuditSeverity("fatal") {
		t.Fatal("fatal 不是合法级别")
	}
	if !validAuditAction(auditActionBlocked) || !validAuditAction(auditActionRepeated) {
		t.Fatal("内置 action 应合法")
	}
	if validAuditAction("allowed") {
		t.Fatal("allowed 不是合法 action")
	}
}

func TestAuditDedupKey(t *testing.T) {
	k1 := auditDedupKey(auditCategoryZip, auditActionBlocked, "zipextract", "越界路径 a/b/c")
	k2 := auditDedupKey(auditCategoryZip, auditActionBlocked, "zipextract", "越界路径 a/b/d")
	if k1 == k2 {
		t.Fatal("不同 detail 前缀的事件不应同键")
	}
	// 只有 96 字符之后的部分不同时，应视为同键。
	samePrefix := strings.Repeat("p", 120)
	k3 := auditDedupKey(auditCategoryZip, auditActionBlocked, "zipextract", samePrefix+"AAA")
	k4 := auditDedupKey(auditCategoryZip, auditActionBlocked, "zipextract", samePrefix+"BBB")
	if k3 != k4 {
		t.Fatal("96 字符之后才不同的 detail 应聚合同键")
	}
}

func TestAuditRecordInvalidDropped(t *testing.T) {
	a := newTestAudit(nil)
	a.record("not-a-category", auditSeverityWarn, auditActionBlocked, "src", "detail")
	if len(a.snapshot("", 10)) != 0 {
		t.Fatal("非法类别事件应被丢弃")
	}
	a.record(auditCategoryZip, "fatal", auditActionBlocked, "src", "detail")
	if len(a.snapshot("", 10)) != 0 {
		t.Fatal("非法级别事件应被丢弃")
	}
}

func TestAuditRingOrderAndCap(t *testing.T) {
	clock := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a := newTestAudit(func() time.Time { return clock })
	for i := 0; i < auditRingCap+25; i++ {
		clock = clock.Add(time.Second)
		// detail 带序号，保证每条不同，不被去重聚合。
		a.record(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "src", "事件序号"+string(rune('A'+i%26))+time.Duration(i).String())
	}
	if len(a.ring) != auditRingCap {
		t.Fatalf("环形缓冲应保持容量 %d，实际 %d", auditRingCap, len(a.ring))
	}
	snap := a.snapshot("", auditRingCap)
	if len(snap) != auditRingCap {
		t.Fatalf("快照数量错误: %d", len(snap))
	}
	if snap[0].OccurredAt.Before(snap[len(snap)-1].OccurredAt) {
		t.Fatal("snapshot 应按时间倒序（最新在前）")
	}
}

func TestAuditDedupAggregates(t *testing.T) {
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	clock := base
	a := newTestAudit(func() time.Time { return clock })

	a.record(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected, "url_policy", "host 不在白名单: evil.example")
	clock = clock.Add(time.Minute)
	a.record(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected, "url_policy", "host 不在白名单: evil.example")
	clock = clock.Add(time.Minute)
	a.record(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected, "url_policy", "host 不在白名单: evil.example")

	snap := a.snapshot("", 10)
	if len(snap) != 1 {
		t.Fatalf("窗口内同键事件应聚合为 1 条，实际 %d", len(snap))
	}
	if snap[0].Count != 3 {
		t.Fatalf("聚合计数应为 3，实际 %d", snap[0].Count)
	}
	if a.suppressed != 2 {
		t.Fatalf("应记录 2 次被压下的重复，实际 %d", a.suppressed)
	}

	// 超过去重窗口再来一次：应落成新条目，并把上一条的重复汇总写出。
	clock = base.Add(auditDedupWindow + time.Minute)
	dir := t.TempDir()
	if err := a.initSecurityAudit(dir); err != nil {
		t.Fatalf("init 失败: %v", err)
	}
	a.record(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected, "url_policy", "host 不在白名单: evil.example")
	if len(a.snapshot("", 10)) != 2 {
		t.Fatal("窗口外事件应成为新条目")
	}
	data, err := os.ReadFile(filepath.Join(dir, auditLogFileName))
	if err != nil {
		t.Fatalf("读审计文件失败: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("窗口外事件 + 一条 repeated 汇总应为 2 行，实际 %d", len(lines))
	}
	var summary SecurityEvent
	if err := json.Unmarshal([]byte(lines[1]), &summary); err != nil {
		t.Fatalf("汇总行不是合法 JSON: %v", err)
	}
	if summary.Action != auditActionRepeated || summary.Count != 2 {
		t.Fatalf("repeated 汇总内容错误: %+v", summary)
	}
}

func TestAuditPersistJSONL(t *testing.T) {
	clock := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	a := newTestAudit(func() time.Time { return clock })
	dir := t.TempDir()
	if err := a.initSecurityAudit(dir); err != nil {
		t.Fatalf("init 失败: %v", err)
	}
	a.record(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "zipextract", "Zip Slip: ../evil")
	clock = clock.Add(10 * time.Second)
	a.record(auditCategoryJVMEnv, auditSeverityWarn, auditActionStripped, "minecraft", "剥离 JAVA_TOOL_OPTIONS")

	data, err := os.ReadFile(filepath.Join(dir, auditLogFileName))
	if err != nil {
		t.Fatalf("读审计文件失败: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("应落盘 2 行，实际 %d", len(lines))
	}
	for i, line := range lines {
		var e SecurityEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON: %v", i+1, err)
		}
		if e.EpochMS != e.OccurredAt.UnixMilli() {
			t.Fatal("EpochMS 与时间戳不一致")
		}
	}

	// 重复 init 幂等，不应重复建文件 / 丢计数。
	if err := a.initSecurityAudit(dir); err != nil {
		t.Fatalf("重复 init 失败: %v", err)
	}
}

// TestAuditInitRejectsDirectoryAtLogPath：审计文件路径被预置成目录时，
// init 必须拒绝，不能把目录当普通文件打开后在其上做追加写入。

// TestAuditInitRejectsSymlinkAtLogPath：审计文件被预置成指向外部文件的符号链接时，
// init 必须拒绝，且链接目标不得被写穿。无法建符号链接的受限环境跳过。
