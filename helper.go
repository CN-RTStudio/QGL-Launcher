package main

import (
	"os"
	"path/filepath"
	"strings"
)

// HelperMinecraftInfo 搜索到的 .minecraft 文件夹信息
type HelperMinecraftInfo struct {
	Path          string   `json:"path"`          // 文件夹完整路径
	FolderName    string   `json:"folderName"`    // 文件夹名（一般为 .minecraft）
	LauncherNames []string `json:"launcherNames"` // 检测到的所有启动器标签（可能多个启动器共用）
}

// HelperModeState 辅助模式状态
type HelperModeState struct {
	Active bool   `json:"active"`
	Dir    string `json:"dir"`
}

// SearchMinecraftFolders 搜索常见的 .minecraft 文件夹位置
// 搜索范围：所有磁盘根目录、用户目录、AppData\Roaming（深度限制 2 层）
func (a *App) SearchMinecraftFolders() ([]HelperMinecraftInfo, error) {
	results := []HelperMinecraftInfo{}
	seen := map[string]bool{}

	// 收集搜索根目录
	searchRoots := []string{}

	// 所有磁盘根目录
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + `:\`
		if _, err := os.Stat(drive); err == nil {
			searchRoots = append(searchRoots, drive)
		}
	}

	// 用户目录
	if home, err := os.UserHomeDir(); err == nil {
		searchRoots = append(searchRoots, home)
		// 用户目录下的常见子目录
		for _, sub := range []string{"Desktop", "Documents", "Downloads"} {
			searchRoots = append(searchRoots, filepath.Join(home, sub))
		}
	}

	// AppData\Roaming
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		searchRoots = append(searchRoots, appdata)
	}

	// 跳过的重目录
	skipNames := map[string]bool{
		"windows": true, "program files": true, "program files (x86)": true,
		"programdata": true, "$recycle.bin": true, "system volume information": true,
		"node_modules": true, "recycle": true, "config": true,
	}

	// BFS 搜索，深度限制 2 层
	type queueItem struct {
		path  string
		depth int
	}
	for _, root := range searchRoots {
		queue := []queueItem{{root, 0}}
		for len(queue) > 0 && len(results) < 30 {
			item := queue[0]
			queue = queue[1:]
			if item.depth > 2 {
				continue
			}

			entries, err := os.ReadDir(item.path)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				name := entry.Name()
				lower := strings.ToLower(name)
				if !entry.IsDir() || strings.HasPrefix(name, "$") || skipNames[lower] {
					continue
				}

				fullPath := filepath.Join(item.path, name)

				// 找到 .minecraft 目录
				if lower == ".minecraft" || lower == "minecraft" {
					if !seen[strings.ToLower(fullPath)] {
						seen[strings.ToLower(fullPath)] = true
						results = append(results, HelperMinecraftInfo{
							Path:          fullPath,
							FolderName:    name,
							LauncherNames: detectLaunchers(fullPath),
						})
					}
					continue
				}

				// 继续向下搜索
				if item.depth < 2 {
					queue = append(queue, queueItem{fullPath, item.depth + 1})
				}
			}
		}
	}

	return results, nil
}

// detectLaunchers 检测 .minecraft 文件夹关联的所有启动器标签
// 多个启动器可能共用同一个 .minecraft，因此检测到特征后不停止，继续检测
// PCL 特征：文件夹中有 PCL.ini
// HMCL 特征：.hmcl 目录 / hmcl.version.json / 上级目录 HMCL-*.jar
// QGL 特征：versions 下任意版本文件夹中有 QGL 文件夹且包含 config.json
// 官方启动器特征：launcher_accounts.json
