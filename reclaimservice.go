package main

import (
	"os"
	"path/filepath"
)

// reclaimservice.go —— 把 partialreaper 内核接到启动器：确定“允许扫哪些根目录”、
// 在启动后异步回收、并给前端暴露一个可手动触发的清理入口。
//
// 根目录采用白名单：回收器只在启动器自有缓存目录与 Minecraft 数据目录内工作，
// 绝不扫描整个磁盘或用户目录。两个根之外的任何文件即使名字命中也不会被删
// （内核在计划与执行两个阶段都做严格归属校验）。

// reclaimRoots 返回本次允许回收的全部根目录（已去重、仅保留存在的目录）。
func (a *App) reclaimRoots() []string {
	seen := map[string]bool{}
	roots := make([]string, 0, 4)
	add := func(p string) {
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil || seen[abs] {
			return
		}
		seen[abs] = true
		if info, statErr := os.Stat(abs); statErr != nil || info == nil || !info.IsDir() {
			return
		}
		roots = append(roots, abs)
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}
	// loader.go 的 qgl_cache（forge 安装器 / 依赖缓存）与其中的临时文件。
	add(filepath.Join(tempDir, "qgl_cache"))
	// 游戏数据目录：版本 / 库 / natives 解压产生的 *.tmp 与散落的孤儿 *.qglmeta。
	add(a.GetMinecraftDir())
	// 数据根也扫一遍，覆盖自定义 MinecraftDir 指向别处时 QGL 自身缓存目录里的残留。
	add(a.GetQGLDir())
	return roots
}
