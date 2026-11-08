package main

// mark_of_web.go 给启动器从互联网下载的文件补 Windows "Mark of the Web"
// （网络来源标记，简称 MOTW）。
//
// 背景：浏览器 / Edge / Chrome 下载文件时，会在文件的 NTFS 备用数据流
// "<文件>:Zone.Identifier" 写入 [ZoneTransfer] 段（ZoneId=3 表示 Internet）。
// Windows 的 SmartScreen、Office 受保护视图、部分安装器策略都依赖这个标记
// 判断"文件来自外部网络"。我们用自己的 HTTP 栈下载 Java 安装包并直接交给
// msiexec / explorer 执行，绕过了浏览器这层标记——结果是一个刚从公网下载
// 的安装包在系统看来和"本机原生文件"没有区别，SmartScreen 不会按互联网来源
// 处置。这里把这道标记补回来。
//
// 平台行为：MOTW 是 NTFS ADS 概念，只在 Windows 写入；其它平台直接 no-op，
// 保证同一份代码可以跨平台编译运行（Go 里冒号文件名在类 Unix 上合法，
// 所以必须用 runtime.GOOS 显式收口，不能靠"打开失败就算了"）。

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

const (
	zoneIdentifierStream = ":Zone.Identifier"
	zoneIDInternet       = 3
	motwMaxURLLength     = 2048
)

var errMarkOfTheWebUnsupported = errors.New("当前平台不支持 Mark of the Web")

// sanitizeZoneURL 清洗写入 ADS 的 URL 值。ADS 是 ini 风格文本，
// 换行会变成新的键甚至新的段，因此任何 CR/LF 都必须拒绝，而不是静默替换。
// 同时限长，避免把超长 Referer 灌进系统元数据。
func sanitizeZoneURL(raw string) (string, error) {
	u := strings.TrimSpace(raw)
	if u == "" {
		return "", nil
	}
	if len(u) > motwMaxURLLength {
		return "", fmt.Errorf("URL 超过 %d 字符", motwMaxURLLength)
	}
	if strings.ContainsAny(u, "\r\n") {
		return "", errors.New("URL 含有非法换行符")
	}
	return u, nil
}

// buildZoneIdentifierBody 生成 Zone.Identifier 数据流内容。
// hostURL 是文件的实际下载地址（必填才有意义）；referrerURL 是发起下载的
// 页面，可空。两条 URL 都经过换行注入校验。
func buildZoneIdentifierBody(hostURL, referrerURL string) (string, error) {
	host, err := sanitizeZoneURL(hostURL)
	if err != nil {
		return "", fmt.Errorf("HostUrl 非法: %w", err)
	}
	referrer, err := sanitizeZoneURL(referrerURL)
	if err != nil {
		return "", fmt.Errorf("ReferrerUrl 非法: %w", err)
	}
	var b strings.Builder
	b.WriteString("[ZoneTransfer]\r\n")
	b.WriteString(fmt.Sprintf("ZoneId=%d\r\n", zoneIDInternet))
	if referrer != "" {
		b.WriteString("ReferrerUrl=" + referrer + "\r\n")
	}
	if host != "" {
		b.WriteString("HostUrl=" + host + "\r\n")
	}
	return b.String(), nil
}

// fileSupportsADS 判断路径所在位置能否承载 NTFS 备用数据流。
// 只做必要的廉价检查：文件存在且是普通文件（符号链接 / 特殊文件一律拒绝，
// 防止把 MOTW 写到链接目标上）。
func fileSupportsADS(targetPath string) error {
	info, err := os.Lstat(targetPath)
	if err != nil {
		return fmt.Errorf("无法读取目标文件状态: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("拒绝给符号链接写入 MOTW")
	}
	if !info.Mode().IsRegular() {
		return errors.New("拒绝给非普通文件写入 MOTW")
	}
	return nil
}

// applyMarkOfTheWeb 在 targetPath 的 Zone.Identifier 数据流写入 Internet 区标记。
// 返回 applied=false 且 err==nil 表示当前平台不支持（非 Windows），调用方
// 应当作正常情况跳过；applied=true 表示标记已写入或覆盖。
func applyMarkOfTheWeb(targetPath, sourceURL string) (bool, error) {
	return applyMarkOfTheWebWithReferrer(targetPath, sourceURL, "")
}

// applyMarkOfTheWebWithReferrer 与 applyMarkOfTheWeb 相同，但允许附带发起页 URL。
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
func readMarkOfTheWeb(targetPath string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", errMarkOfTheWebUnsupported
	}
	data, err := os.ReadFile(targetPath + zoneIdentifierStream)
	if err != nil {
		return "", err
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
