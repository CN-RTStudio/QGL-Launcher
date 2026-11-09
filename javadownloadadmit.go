package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

const maxJavaArtifactNameLen = 120

const (
	jdRejectNone           = ""
	jdRejectUnknownMajor   = "java-unknown-major"
	jdRejectBadName        = "java-bad-filename"
	jdRejectBadCatalogURL  = "java-bad-catalog-url"
	jdRejectURLMismatch    = "java-url-mismatch"
	jdRejectUnsafeArtifact = "java-unsafe-artifact"
)

var javaArtifactExtensions = map[string]bool{
	".zip": true,
	".msi": true,
	".exe": true,
	".pkg": true,
	".dmg": true,
}

func findJavaDownloadInfo(list []JavaDownloadInfo, major int) (JavaDownloadInfo, bool) {
	for i := range list {
		if list[i].MajorVer == major {
			return list[i], true
		}
	}
	return JavaDownloadInfo{}, false
}

func auditJavaArtifactName(name string) string {
	if strings.TrimSpace(name) == "" {
		return jdRejectBadName
	}
	if len(name) > maxJavaArtifactNameLen {
		return jdRejectBadName
	}
	if containsControlChar(name) {
		return jdRejectBadName
	}
	if strings.ContainsAny(name, `/\:*?"<>|`) {
		return jdRejectBadName
	}
	if name == "." || name == ".." || strings.HasPrefix(name, "..") {
		return jdRejectBadName
	}
	if !javaArtifactExtensions[strings.ToLower(filepath.Ext(name))] {
		return jdRejectUnsafeArtifact
	}
	return jdRejectNone
}

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
