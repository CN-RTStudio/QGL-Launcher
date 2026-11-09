package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

func uniqueStrings(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || m[s] {
			continue
		}
		m[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SummarizeUpdateVerdict 把校验结论压成便于展示的纯文本（不参与判定）。
func SummarizeUpdateVerdict(v UpdateVerdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OK=%v entries=%d bytes=%d singleRoot=%v launcherExe=%v",
		v.OK, v.ZipEntryCount, v.ZipTotalBytes, v.HasSingleRoot, v.HasLauncherExe)
	for _, f := range v.Findings {
		fmt.Fprintf(&b, " [%s:%s %s]", f.Severity, f.Code, f.Message)
	}
	return b.String()
}

// validateUpdateDescRune 用于描述串的 rune 级检查（与 sanitizeUpdateDesc 同源，
// 供单测直接断言边界）。
func validateUpdateDescRune(r rune) bool {
	return !(r < 0x20 && r != '\n' && r != '\t')
}

// hasControlCharStr 已在 modsaudit.go 定义，此处复用，不再重复声明。

// readZipEntryText 读取 zip 条目文本（有界），供校验器对更新说明 / 元数据做
// 二次检查时使用；超过上限直接失败，不放大内存。
func readZipEntryText(f *zip.File, maxBytes int64) (string, error) {
	if f.UncompressedSize64 > uint64(maxBytes) {
		return "", errors.New("条目超过读取上限")
	}
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	limited := io.LimitReader(rc, maxBytes+1)
	buf := make([]byte, 0, int(f.UncompressedSize64+1))
	tmp := make([]byte, 4096)
	for {
		n, err := limited.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if int64(len(buf)) > maxBytes {
			return "", errors.New("条目超过读取上限")
		}
	}
	// 控制字符检测（允许 \n \t）。
	for _, r := range string(buf) {
		if !validateUpdateDescRune(r) {
			return "", errors.New("条目含控制字符")
		}
	}
	return string(buf), nil
}

// 导出版本比较与 URL 校验的别名函数，供测试与调用方统一入口。
func ValidateUpdateUrl(raw string, limits UpdateLimits) (bool, string, string) {
	return sanitizeUpdateUrl(raw, limits)
}

func ValidateUpdateAssetName(name string, limits UpdateLimits) (string, bool) {
	return sanitizeUpdateAssetName(name, limits)
}
