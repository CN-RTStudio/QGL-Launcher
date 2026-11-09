package main

import (
	"fmt"
	"os"
	"strings"
)

func (a *App) ToggleMod(modFilePath string, enable bool) error {
	mcDir := a.GetMinecraftDir()
	// 只允许操作“受管 mods 目录”（全局 mods 或版本隔离 mods）顶层的 .jar/.jar.disabled。
	// 旧实现只判定 PathWithin(mcDir)，等于放权整个 .minecraft，渲染层可借改名禁用
	// libraries/versions 里的任意 jar（破坏依赖）；这里收口到受管集合。
	curAbs, ok := resolveManagedModPath(mcDir, modFilePath)
	if !ok {
		recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
			"ToggleMod", "拒绝切换受管 Mods 目录之外的文件: "+modFilePath)
		return fmt.Errorf("只能切换 Mods 目录内的 .jar 文件")
	}
	if _, err := os.Stat(curAbs); err != nil {
		return fmt.Errorf("文件不存在: %s", modFilePath)
	}

	var newPath string
	if enable {
		if strings.HasSuffix(strings.ToLower(curAbs), disabledJarSuffix) {
			newPath = curAbs[:len(curAbs)-len(".disabled")]
		} else {
			return nil
		}
	} else {
		if strings.HasSuffix(strings.ToLower(curAbs), jarSuffix) {
			newPath = curAbs + ".disabled"
		} else {
			return nil
		}
	}

	// 改名目标也必须落在同一受管 mods 目录、且仍是受管 jar，防止借启用/禁用把文件
	// 挪出 mods 目录或挪成非受管文件（防御纵深：正常情况下仅后缀变化，父目录不变）。
	toAbs, ok := resolveManagedModPath(mcDir, newPath)
	if !ok || !sameManagedModDir(curAbs, toAbs) {
		recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
			"ToggleMod", "拒绝把 Mod 改名到受管 Mods 目录之外: "+newPath)
		return fmt.Errorf("非法的 Mod 目标路径")
	}

	if err := os.Rename(curAbs, toAbs); err != nil {
		return fmt.Errorf("重命名失败: %v", err)
	}

	return nil
}
