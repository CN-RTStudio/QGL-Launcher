package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	wslReasonOK            = "ok"
	wslReasonMissing       = "missing"
	wslReasonNotDirectory  = "not-directory"
	wslReasonSymlink       = "symlink"
	wslReasonUnreadable    = "unreadable"
	wslReasonTooLarge      = "too-large"
	wslReasonBadLevelDat   = "bad-level-dat"
	wslReasonWorldInUse    = "world-in-use"
	wslReasonLockStale     = "lock-stale"
	wslReasonWorldReadable = "world-readable"
	wslReasonMissingLock   = "missing-lock"

	wslMaxLevelDatBytes = 16 << 20
	wslInUseWindow      = 30 * time.Minute
	wslStaleLockWindow  = 90 * 24 * time.Hour
	wslMaxWorlds        = 8
	wslMaxFindings      = 48
)

var wslWorldCandidates = []string{
	"world",
	"world_nether",
	"world_the_end",
	filepath.Join("world", "DIM-1"),
	filepath.Join("world", "DIM1"),
}

type SessionLockFinding struct {
	World    string
	Reason   string
	Detail   string
	Blocking bool
}

type SessionLockAudit struct {
	Dir      string
	Now      time.Time
	Worlds   []string
	Findings []SessionLockFinding
}

func (a SessionLockAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f SessionLockFinding) bool { return f.Blocking })
}

func (a SessionLockAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f SessionLockFinding) bool { return !f.Blocking && f.Reason != wslReasonOK })
}

func (a SessionLockAudit) Codes() []string {
	return findingCodesSkip(a.Findings, wslReasonOK, func(f SessionLockFinding) string { return f.Reason })
}

func (a SessionLockAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现世界目录"
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s)", f.World, f.Reason))
		if len(parts) >= 4 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a SessionLockAudit) Summary() string {
	blocking, warnings := 0, 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != wslReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("worlds=%d findings=%d blocking=%d warnings=%d", len(a.Worlds), len(a.Findings), blocking, warnings)
}

func (a *SessionLockAudit) add(world, reason, detail string, blocking bool) {
	if len(a.Findings) >= wslMaxFindings {
		return
	}
	a.Findings = append(a.Findings, SessionLockFinding{World: world, Reason: reason, Detail: detail, Blocking: blocking})
}

func wslCheckLevelDat(audit *SessionLockAudit, world, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.add(world, wslReasonMissing, "缺少 level.dat", false)
			return
		}
		audit.add(world, wslReasonUnreadable, "level.dat 不可访问", true)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(world, wslReasonSymlink, "level.dat 是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(world, wslReasonUnreadable, "level.dat 不是普通文件", true)
		return
	}
	if info.Size() > wslMaxLevelDatBytes {
		audit.add(world, wslReasonTooLarge, "level.dat 超过体积预算", true)
		return
	}
	if info.Size() < 32 {
		audit.add(world, wslReasonBadLevelDat, "level.dat 体积异常", true)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		audit.add(world, wslReasonUnreadable, "level.dat 读取失败", true)
		return
	}
	head := make([]byte, 2)
	_, readErr := f.Read(head)
	f.Close()
	if readErr != nil {
		audit.add(world, wslReasonUnreadable, "level.dat 头部读取失败", true)
		return
	}
	if head[0] != 0x1f || head[1] != 0x8b {
		audit.add(world, wslReasonBadLevelDat, "level.dat 不是 gzip 压缩的 NBT", true)
	}
}

func wslCheckLock(audit *SessionLockAudit, world, path string, now time.Time) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.add(world, wslReasonMissingLock, "缺少 session.lock", false)
			return
		}
		audit.add(world, wslReasonUnreadable, "session.lock 不可访问", true)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(world, wslReasonSymlink, "session.lock 是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(world, wslReasonUnreadable, "session.lock 不是普通文件", true)
		return
	}
	if info.ModTime().After(now.Add(-wslInUseWindow)) {
		audit.add(world, wslReasonWorldInUse, "session.lock 最近被写入，世界可能仍被服务器占用", true)
		return
	}
	if info.ModTime().Before(now.Add(-wslStaleLockWindow)) {
		audit.add(world, wslReasonLockStale, "session.lock 长期未更新，可能残留自异常退出", false)
	}
}

func wslCheckWorld(audit *SessionLockAudit, serverDir, world string, now time.Time) {
	path := filepath.Join(serverDir, world)
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(world, wslReasonSymlink, "世界目录是符号链接", true)
		return
	}
	if !info.IsDir() {
		audit.add(world, wslReasonNotDirectory, "世界路径不是目录", true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		audit.add(world, wslReasonWorldReadable, "世界目录对其他用户可写", false)
	}
	audit.Worlds = append(audit.Worlds, world)
	wslCheckLevelDat(audit, world, filepath.Join(path, "level.dat"))
	wslCheckLock(audit, world, filepath.Join(path, "session.lock"), now)
}

func auditServerSessionLocksAt(serverDir string, now time.Time) SessionLockAudit {
	audit := SessionLockAudit{Dir: serverDir, Now: now}
	for _, world := range wslWorldCandidates {
		if len(audit.Worlds) >= wslMaxWorlds {
			audit.add(world, wslReasonTooLarge, "世界数量超过预算", true)
			break
		}
		wslCheckWorld(&audit, serverDir, world, now)
	}
	if len(audit.Findings) == 0 {
		audit.add("", wslReasonOK, "世界目录状态正常", false)
	}
	return audit
}

func AuditServerSessionLocks(serverDir string) SessionLockAudit {
	return auditServerSessionLocksAt(serverDir, time.Now())
}
