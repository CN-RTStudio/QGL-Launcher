package main

import (
	"os"
	"path/filepath"
	"time"
)

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
