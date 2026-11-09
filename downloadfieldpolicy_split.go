package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func auditDownloadItemFields(item DownloadItem, mcDir string) string {
	if why := auditDownloadSavePath(item, mcDir); why != dfRejectNone {
		return why
	}
	switch item.ItemType {
	case "java":
		if item.JavaMajor < 8 || item.JavaMajor > 99 {
			return dfRejectJavaMajor
		}
	case "game+loader":
		if !allowedLoaderNames[item.LoaderName] {
			return dfRejectLoaderName
		}
		if strings.TrimSpace(item.LoaderVersion) == "" {
			return dfRejectLoaderVersion
		}
		if item.LoaderName == "optifine" {
			if strings.TrimSpace(item.OptiFineType) == "" || strings.TrimSpace(item.OptiFinePatch) == "" {
				return dfRejectOptiFine
			}
		}
	case "mod":
		if !allowedModExtensions[strings.ToLower(filepath.Ext(item.CustomName))] {
			return dfRejectModExt
		}
	}
	return dfRejectNone
}

func describeDownloadFieldReject(code string) string {
	switch code {
	case dfRejectSavePath:
		return "下载保存路径必须是 .minecraft 目录内的规范绝对路径"
	case dfRejectJavaMajor:
		return "Java 安装任务的主版本号超出受支持范围"
	case dfRejectLoaderName:
		return "加载器任务使用了未知的加载器名称"
	case dfRejectLoaderVersion:
		return "加载器任务缺少加载器版本"
	case dfRejectOptiFine:
		return "OptiFine 任务缺少安装类型或补丁版本"
	case dfRejectModExt:
		return fmt.Sprintf("Mod 任务文件名扩展名不在允许列表内（%s / %s / %s）", ".jar", ".zip", ".disabled")
	default:
		return "下载任务字段未通过安全校验"
	}
}
