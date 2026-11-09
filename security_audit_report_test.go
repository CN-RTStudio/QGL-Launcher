package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
