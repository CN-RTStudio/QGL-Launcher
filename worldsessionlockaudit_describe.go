package main

import (
	"fmt"
	"os"
)

func (a SessionLockAudit) Describe() string {
	return describeLabeledFindings("未发现世界目录", a.Findings, 4, "",
		func(f SessionLockFinding) string { return f.World },
		func(f SessionLockFinding) string { return f.Reason })
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
