package main

import (
	"errors"
	"fmt"
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
