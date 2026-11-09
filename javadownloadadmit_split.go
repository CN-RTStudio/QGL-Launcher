package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func auditJavaDownloadRequest(major int, requestedURL string, list []JavaDownloadInfo) (JavaDownloadInfo, string) {
	target, ok := findJavaDownloadInfo(list, major)
	if !ok {
		return JavaDownloadInfo{}, jdRejectUnknownMajor
	}
	if why := auditJavaArtifactName(target.FileName); why != jdRejectNone {
		return JavaDownloadInfo{}, why
	}
	if target.URL == "" {
		return JavaDownloadInfo{}, jdRejectBadCatalogURL
	}
	if why := auditDownloadQueueURL(target.URL); why != dqURLRejectNone {
		return JavaDownloadInfo{}, jdRejectBadCatalogURL
	}
	if requestedURL != "" && requestedURL != target.URL {
		return JavaDownloadInfo{}, jdRejectURLMismatch
	}
	if target.IsMSI && !strings.EqualFold(filepath.Ext(target.FileName), ".msi") {
		return JavaDownloadInfo{}, jdRejectUnsafeArtifact
	}
	if target.IsZip && !strings.EqualFold(filepath.Ext(target.FileName), ".zip") {
		return JavaDownloadInfo{}, jdRejectUnsafeArtifact
	}
	return target, jdRejectNone
}

func describeJavaDownloadReject(code string) string {
	switch code {
	case jdRejectUnknownMajor:
		return "请求的 Java 主版本不在受支持列表内"
	case jdRejectBadName:
		return "Java 安装包文件名未通过安全校验"
	case jdRejectBadCatalogURL:
		return "Java 下载地址不是可接受的 HTTPS 公网地址"
	case jdRejectURLMismatch:
		return "下载队列中的 Java 地址与受信任目录不一致，已拒绝"
	case jdRejectUnsafeArtifact:
		return fmt.Sprintf("Java 安装包类型与声明格式不符（仅允许 %s）", strings.Join([]string{".zip", ".msi", ".exe", ".pkg", ".dmg"}, " / "))
	default:
		return "Java 下载请求未通过安全检查"
	}
}
