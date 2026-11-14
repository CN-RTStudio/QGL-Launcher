package main

import (
	"os"
	"path/filepath"
	"strings"
)

func detectLaunchers(mcDir string) []string {
	tags := []string{}
	addTag := func(name string) {
		for _, t := range tags {
			if t == name {
				return
			}
		}
		tags = append(tags, name)
	}

	parent := filepath.Dir(mcDir)

	// PCL: PCL.ini 存在于 .minecraft 目录或上级目录（PCL.exe 所在处）
	if _, err := os.Stat(filepath.Join(mcDir, "PCL.ini")); err == nil {
		addTag("PCL")
	} else if _, err := os.Stat(filepath.Join(parent, "PCL.ini")); err == nil {
		addTag("PCL")
	}

	// HMCL: .hmcl 目录
	if info, err := os.Stat(filepath.Join(mcDir, ".hmcl")); err == nil && info.IsDir() {
		addTag("HMCL")
	}
	// HMCL: hmcl.version.json
	if _, err := os.Stat(filepath.Join(mcDir, "hmcl.version.json")); err == nil {
		addTag("HMCL")
	}
	// HMCL: 上级目录有 HMCL-*.jar
	if entries, err := os.ReadDir(parent); err == nil {
		for _, e := range entries {
			lower := strings.ToLower(e.Name())
			if strings.HasPrefix(lower, "hmcl-") && strings.HasSuffix(lower, ".jar") {
				addTag("HMCL")
				break
			}
		}
	}

	// QGL: versions 下任意版本文件夹中有 QGL/config.json
	if versionsDir, err := os.ReadDir(filepath.Join(mcDir, "versions")); err == nil {
		for _, v := range versionsDir {
			if !v.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(mcDir, "versions", v.Name(), "QGL", "config.json")); err == nil {
				addTag("QGL")
				break
			}
		}
	}

	// 官方启动器特征
	if _, err := os.Stat(filepath.Join(mcDir, "launcher_accounts.json")); err == nil {
		addTag("Official")
	}

	return tags
}

// GetHelperMode 获取辅助模式状态
