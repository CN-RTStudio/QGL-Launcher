package main

import (
	"fmt"
	"os"
	"runtime"
)

func applyMarkOfTheWebWithReferrer(targetPath, sourceURL, referrerURL string) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, nil
	}
	if err := fileSupportsADS(targetPath); err != nil {
		return false, err
	}
	body, err := buildZoneIdentifierBody(sourceURL, referrerURL)
	if err != nil {
		return false, err
	}
	stream, err := os.OpenFile(targetPath+zoneIdentifierStream,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, privateFilePerm)
	if err != nil {
		return false, fmt.Errorf("打开 Zone.Identifier 数据流失败: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			stream.Close()
		}
	}()
	if _, err := stream.WriteString(body); err != nil {
		stream.Close()
		closed = true
		// 写入失败时尝试清掉半条数据流，避免留下截断的 ini。
		_ = os.Remove(targetPath + zoneIdentifierStream)
		return false, fmt.Errorf("写入 Zone.Identifier 失败: %w", err)
	}
	if err := stream.Close(); err != nil {
		closed = true
		return false, fmt.Errorf("关闭 Zone.Identifier 失败: %w", err)
	}
	return true, nil
}

// readMarkOfTheWeb 读回 MOTW 内容，供自检 / 诊断使用；非 Windows 返回
// errMarkOfTheWebUnsupported。
const markOfTheWebMaxBytes = 64 << 10

func readMarkOfTheWeb(targetPath string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", errMarkOfTheWebUnsupported
	}
	data, err := os.ReadFile(targetPath + zoneIdentifierStream)
	if err != nil {
		return "", err
	}
	if len(data) > markOfTheWebMaxBytes {
		data = data[:markOfTheWebMaxBytes]
	}
	return string(data), nil
}

// markDownloadWithWebOrigin 是给下载链用的便捷封装：写入失败只审计、不阻断
// 主流程（MOTW 是纵深防御，不能因为它写失败就让用户用不了已校验的文件）。
// 返回 true 仅在 Windows 且标记成功时成立。
func markDownloadWithWebOrigin(targetPath, sourceURL, referrerURL string) bool {
	applied, err := applyMarkOfTheWebWithReferrer(targetPath, sourceURL, referrerURL)
	if err != nil {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"mark-of-web", "下载文件写入网络来源标记失败: "+sanitizeAuditDetail(err.Error()))
		return false
	}
	return applied
}
