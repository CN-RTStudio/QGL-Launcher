package main

import (
	"os"
	"path/filepath"
	"strings"
)

func sanitizeServerName(name string) string {
	name = strings.TrimSpace(name)
	replacer := strings.NewReplacer(
		"..", "", "/", "", "\\", "", ":", "", "*", "", "?", "",
		"\"", "", "<", "", ">", "", "|", "", "\n", "", "\r", "",
	)
	name = replacer.Replace(name)
	if name == "" {
		return ""
	}
	if containsControlByte(name) {
		return ""
	}
	// 默认流程会用 name 直接做服务器目录名：拒绝 Windows 保留设备名（CON 等）与尾点，
	// 避免目录被导向设备或与已存在目录发生静默同名（Windows 会剥掉尾点）。
	if isReservedDeviceName(stemOfName(name)) {
		return ""
	}
	if strings.HasSuffix(name, ".") {
		return ""
	}
	if len(name) > maxServerNameLen {
		return ""
	}
	return name
}

// isPathTraversal 检查目标路径是否存在路径遍历风险
func isPathTraversal(baseDir, targetPath string) bool {
	resolvedBase, err := filepath.Abs(baseDir)
	if err != nil {
		return true
	}
	resolvedTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return true
	}
	return !strings.HasPrefix(resolvedTarget, resolvedBase+string(os.PathSeparator)) && resolvedTarget != resolvedBase
}

// isStrictSubdir 判断 target 是否为 base 的“严格子目录”：
// 解析符号链接后，target 既不能等于 base，也不能是 base 的父级或越出 base。
// 删除单个服务器时必须用它（而非 isPathTraversal），否则被篡改的 ServerDir
// 若等于服务器根目录，RemoveAll 会一次性清空所有服务器。
func isStrictSubdir(base, target string) bool {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	// 拒绝直接对盘符 / 卷根动手，避免误删整盘。
	if strings.TrimRight(targetAbs, string(os.PathSeparator)) == filepath.VolumeName(targetAbs) {
		return false
	}
	// 尽量解析到真实路径，挫败“服务器目录是指向根目录 / 其外部的符号链接”。
	if real, err := filepath.EvalSymlinks(targetAbs); err == nil {
		targetAbs = real
	}
	if realBase, err := filepath.EvalSymlinks(baseAbs); err == nil {
		baseAbs = realBase
	}
	if targetAbs == baseAbs {
		return false
	}
	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	return true
}

// GetServerDir 获取服务器根目录
func (a *App) GetServerDir() string {
	return filepath.Join(a.GetQGLDir(), "server")
}

// GetServerList 获取服务器列表
func (a *App) GetServerList() ([]ServerConfig, error) {
	serverDir := a.GetServerDir()
	if _, err := os.Stat(serverDir); os.IsNotExist(err) {
		return []ServerConfig{}, nil
	}
	entries, err := os.ReadDir(serverDir)
	if err != nil {
		return nil, err
	}
	var list []ServerConfig
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		configPath := filepath.Join(serverDir, entry.Name(), "QGL", "config.json")
		var cfg ServerConfig
		if err := readPrivateStoreJSON(configPath, &cfg, "服务器配置"); err != nil {
			continue
		}
		// 跳过任何被篡改 / 字段非法的配置，避免把带病条目暴露给前端和执行路径。
		if err := a.validateLoadedServerConfig(&cfg); err != nil {
			continue
		}
		list = append(list, cfg)
	}
	return list, nil
}

// CreateServer 创建服务器
