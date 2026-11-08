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

func TestAuditPersistFailureNeverPanics(t *testing.T) {
	a := newTestAudit(nil)
	// 未 init：事件只进内存，不应报错 / panic。
	a.record(auditCategoryInstaller, auditSeverityWarn, auditActionBlocked, "installer", "未初始化阶段事件")
	if len(a.snapshot("", 10)) != 1 {
		t.Fatal("未 init 时事件仍应进入内存环")
	}
	// 清空也不应因为文件不存在报错。
	if err := a.clear(); err != nil {
		t.Fatalf("未 init 时 clear 应无错误: %v", err)
	}
}

func TestAuditRotation(t *testing.T) {
	dir := t.TempDir()
	a := newTestAudit(nil)
	if err := a.initSecurityAudit(dir); err != nil {
		t.Fatalf("init 失败: %v", err)
	}
	// 手工把文件尺寸推到阈值之上，下一次写应触发轮转。
	logPath := filepath.Join(dir, auditLogFileName)
	if err := os.WriteFile(logPath, []byte(strings.Repeat("x", 100)+"\n"), privateFilePerm); err != nil {
		t.Fatalf("预置日志失败: %v", err)
	}
	a.mu.Lock()
	a.fileSize = auditMaxFileBytes
	a.mu.Unlock()

	a.record(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "src", "触发轮转事件")
	if _, err := os.Lstat(logPath + auditLogArchiveSuffix); err != nil {
		t.Fatalf("应产生归档文件: %v", err)
	}
	if info, err := os.Stat(logPath); err != nil || info.Size() == 0 {
		t.Fatal("轮转后应存在新的非空日志文件")
	}

	// 再来一轮：旧归档被删除替换，磁盘上最多一份归档。
	a.mu.Lock()
	a.fileSize = auditMaxFileBytes
	a.mu.Unlock()
	a.record(auditCategoryHashVerify, auditSeverityWarn, auditActionBlocked, "src", "第二次轮转事件")
	if _, err := os.Lstat(logPath + auditLogArchiveSuffix); err != nil {
		t.Fatalf("第二次轮转后归档仍应存在: %v", err)
	}
}

func TestAuditSnapshotCategoryFilterAndLimit(t *testing.T) {
	a := newTestAudit(nil)
	a.record(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "s1", "zip 一")
	a.record(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected, "s2", "url 一")
	a.record(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "s3", "zip 二")

	zips := a.snapshot(auditCategoryZip, 10)
	if len(zips) != 2 {
		t.Fatalf("zip 类别应有 2 条，实际 %d", len(zips))
	}
	if zips[0].Detail != "zip 二" {
		t.Fatal("过滤结果仍应最新在前")
	}
	if got := a.snapshot("", 1); len(got) != 1 || got[0].Detail != "zip 二" {
		t.Fatal("limit=1 只应返回最新一条")
	}
}

func TestAuditClear(t *testing.T) {
	dir := t.TempDir()
	a := newTestAudit(nil)
	if err := a.initSecurityAudit(dir); err != nil {
		t.Fatalf("init 失败: %v", err)
	}
	a.record(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "s", "待清除")
	if err := a.clear(); err != nil {
		t.Fatalf("clear 失败: %v", err)
	}
	if len(a.snapshot("", 10)) != 0 {
		t.Fatal("clear 后内存环应为空")
	}
	if _, err := os.Lstat(filepath.Join(dir, auditLogFileName)); !os.IsNotExist(err) {
		t.Fatal("clear 后磁盘日志应不存在")
	}
}

func TestAuditEmptyDirRejected(t *testing.T) {
	a := newTestAudit(nil)
	if err := a.initSecurityAudit("   "); err == nil {
		t.Fatal("空审计目录应报错")
	}
}

func TestDefaultAuditPackageAPI(t *testing.T) {
	// 包级 API 不应 panic，默认实例可用。
	recordSecurityEvent(auditCategoryRateLimit, auditSeverityInfo, auditActionRejected, "test", "包级记录测试")
	got := snapshotSecurityEvents(auditCategoryRateLimit, 5)
	found := false
	for _, e := range got {
		if e.Source == "test" {
			found = true
		}
	}
	if !found {
		t.Fatal("包级 recordSecurityEvent 写入的事件读不回来")
	}
	// 清掉默认实例，避免污染其他测试。
	if err := clearSecurityEvents(); err != nil {
		t.Fatalf("清理默认审计实例失败: %v", err)
	}
}

// TestAuditInitRejectsDirectoryAtLogPath：审计文件路径被预置成目录时，
// init 必须拒绝，不能把目录当普通文件打开后在其上做追加写入。
func TestAuditInitRejectsDirectoryAtLogPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, auditLogFileName), 0o700); err != nil {
		t.Fatalf("预置同名目录失败: %v", err)
	}
	a := newTestAudit(nil)
	if err := a.initSecurityAudit(dir); err == nil {
		t.Fatal("审计路径是目录时 init 应当失败")
	}
	if a.initialized {
		t.Fatal("初始化失败后审计器不应被标记为已启用")
	}
}

// TestAuditInitRejectsSymlinkAtLogPath：审计文件被预置成指向外部文件的符号链接时，
// init 必须拒绝，且链接目标不得被写穿。无法建符号链接的受限环境跳过。
func TestAuditInitRejectsSymlinkAtLogPath(t *testing.T) {
	auditDir := t.TempDir()
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "outside.txt")
	if err := os.WriteFile(target, []byte("keep-me"), 0o600); err != nil {
		t.Fatalf("准备外部目标失败: %v", err)
	}
	link := filepath.Join(auditDir, auditLogFileName)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境无法创建符号链接，跳过: %v", err)
	}
	a := newTestAudit(nil)
	if err := a.initSecurityAudit(auditDir); err == nil {
		t.Fatal("审计路径是符号链接时 init 应当失败")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("读取目标失败: %v", err)
	}
	if string(got) != "keep-me" {
		t.Fatalf("符号链接目标被写穿: %q", string(got))
	}
}
