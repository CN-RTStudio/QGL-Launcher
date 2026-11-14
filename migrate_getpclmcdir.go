package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

)

func (a *App) GetPclMcDir(pclExePath string) (string, error) {
	pclExePath = strings.TrimSpace(pclExePath)
	if pclExePath == "" {
		return "", fmt.Errorf("请先选择 PCL 可执行文件")
	}
	if _, err := os.Stat(pclExePath); err != nil {
		return "", fmt.Errorf("PCL 可执行文件不存在: %s", pclExePath)
	}

	setupPath := filepath.Join(filepath.Dir(pclExePath), "PCL", "Setup.ini")
	data, err := os.ReadFile(setupPath)
	if err != nil {
		return "", fmt.Errorf("未找到 PCL 配置文件（PCL\\Setup.ini），请确认选择的是 PCL 启动器")
	}

	// 解析 key:value 行
	mcDir := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key == "LaunchFolderSelect" && value != "" {
			mcDir = value
		}
	}

	if mcDir == "" {
		return "", fmt.Errorf("PCL 配置中没有设置游戏目录（LaunchFolderSelect）")
	}

	// 校验目录存在
	if info, err := os.Stat(mcDir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("PCL 的游戏目录不存在: %s", mcDir)
	}

	return mcDir, nil
}

// MigrateMinecraftDir 迁移 .minecraft 目录
// mode = "full"：完整迁移，复制整个 .minecraft 到 QGL 目录（独立副本，PCL 出问题不影响 QGL）
// mode = "minimal"：最小迁移，仅把 QGL 的游戏目录指向 PCL 的 .minecraft（共用，PCL 出问题 QGL 一起出问题）
// 返回迁移后的实际游戏目录
func (a *App) MigrateMinecraftDir(srcDir string, mode string) (string, error) {
	srcDir = strings.TrimSpace(srcDir)
	if srcDir == "" {
		return "", fmt.Errorf("请先选择 .minecraft 文件夹")
	}
	info, err := os.Stat(srcDir)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("目录不存在: %s", srcDir)
	}

	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}

	var finalDir string
	if mode == "minimal" {
		// 最小迁移：直接指向原目录
		config.MinecraftDir = srcDir
		finalDir = srcDir
	} else {
		// 完整迁移：复制到 QGL 目录
		targetDir := filepath.Join(a.GetQGLDir(), ".minecraft")
		if err := copyDirRecursive(srcDir, targetDir); err != nil {
			return "", fmt.Errorf("复制 .minecraft 失败: %w", err)
		}
		config.MinecraftDir = ""
		finalDir = targetDir
	}

	// 注意：不修改辅助模式状态，辅助模式必须由用户手动进入

	if err := a.SaveGlobalConfig(config); err != nil {
		return "", err
	}
	return finalDir, nil
}

// copyDirRecursive 递归复制目录（已存在则合并覆盖）
func copyDirRecursive(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		// 跳过 PCL 自己的缓存/标记文件（PCL.ini、PCL 文件夹），这些不属于游戏数据
		relLower := strings.ToLower(rel)
		if relLower == "pcl.ini" || strings.HasPrefix(relLower, "pcl\\") || strings.HasPrefix(relLower, "pcl/") {
			return nil
		}

		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		dstFile, err := os.Create(target)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		return err
	})
}
