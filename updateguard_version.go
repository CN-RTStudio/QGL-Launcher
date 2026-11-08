package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

func ParseVersionParts(v string, limits UpdateLimits) [][]string {
	l := limits.withDefaults()
	if v == "" || len(v) > l.UrlLenMax/2 {
		return nil
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return nil
		}
	}
	raw := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
	if len(raw) == 0 || len(raw) > l.VersionParts {
		return nil
	}
	parts := make([][]string, 0, len(raw))
	for _, tok := range raw {
		if tok == "" {
			return nil
		}
		parts = append(parts, []string{tok})
	}
	return parts
}

// CompareVersionTokens 比较两个已拆好的版本 token 序列。
// 返回值 <0 / 0 / >0 对应 a<b / a==b / a>b。
// 规则：数字 token 数值比较（'9' < '10'）；字母 token 按 rune 字典序；
// 数字 token 整体小于字母 token；段数不同时缺段视为 0（数字）或空（字母）。
func CompareVersionTokens(a, b [][]string) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		var av, bv string
		if i < len(a) {
			av = a[i][0]
		}
		if i < len(b) {
			bv = b[i][0]
		}
		if av == bv {
			continue
		}
		aNum, aIsNum := numericToken(av)
		bNum, bIsNum := numericToken(bv)
		switch {
		case aIsNum && bIsNum:
			if aNum < bNum {
				return -1
			}
			if aNum > bNum {
				return 1
			}
		case aIsNum != bIsNum:
			if aIsNum {
				return -1
			}
			return 1
		default:
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func numericToken(s string) (int64, bool) {
	if s == "" {
		return 0, true // 缺段视为数字 0
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// IsVersionNewer 判断候选版本是否比当前版本"更新"（语义比较）。
func IsVersionNewer(candidate, current string, limits UpdateLimits) (bool, error) {
	c := ParseVersionParts(candidate, limits)
	cur := ParseVersionParts(current, limits)
	if c == nil || cur == nil {
		return false, errors.New("版本号格式非法")
	}
	return CompareVersionTokens(c, cur) > 0, nil
}

// sanitizeUpdateDesc 校验更新说明：限长、拒绝控制字符。
func sanitizeUpdateDesc(desc string, limits UpdateLimits) (string, bool) {
	l := limits.withDefaults()
	if desc == "" {
		return desc, true
	}
	if len([]rune(desc)) > l.DescRunesMax {
		return "", false
	}
	for _, r := range desc {
		if r < 0x20 && r != '\n' && r != '\t' {
			return "", false
		}
	}
	return desc, true
}

// InspectUpdateZip 只读预检更新包 zip：条目路径全部过 secureZipRelPath；
// 拒绝符号链接 / 设备条目；条目数与总大小设上限；记录是否存在单一顶层目录
// 与启动器可执行入口（*.exe / 二进制根文件）。不落盘任何内容。
func InspectUpdateZip(zr *zip.Reader, limits UpdateLimits) UpdateVerdict {
	l := limits.withDefaults()
	v := UpdateVerdict{OK: true, Findings: []UpdateFindings{}}
	seen := map[string]bool{}
	var rootDirs []string
	hasExe := false
	rootEntries := 0

	for _, f := range zr.File {
		v.ZipEntryCount++
		if v.ZipEntryCount > l.ZipEntriesMax {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-entries-overflow",
				fmt.Sprintf("更新包条目数超过上限 %d", l.ZipEntriesMax)})
			return v
		}
		if f.UncompressedSize64 > uint64(l.ZipBytesMax) {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-entry-too-big",
				fmt.Sprintf("条目 %s 超过总量上限", f.Name)})
			return v
		}
		v.ZipTotalBytes += int64(f.UncompressedSize64)
		if v.ZipTotalBytes > l.ZipBytesMax {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-total-overflow",
				"更新包解压后总大小超过上限"})
			return v
		}

		if f.Mode()&(osModeSymlink|osModeDevice) != 0 {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-special-entry",
				fmt.Sprintf("更新包含符号链接/设备条目: %s", f.Name)})
			continue
		}

		rel, ok := secureZipRelPath(f.Name)
		if !ok {
			v.OK = false
			v.Findings = append(v.Findings, UpdateFindings{"error", "zip-unsafe-path",
				fmt.Sprintf("更新包含不安全路径条目: %s", f.Name)})
			continue
		}
		if seen[rel] {
			continue // 重复条目只审计一次
		}
		seen[rel] = true

		dir := path.Dir(rel)
		if dir == "." {
			rootEntries++
		} else {
			top := strings.Split(dir, "/")[0]
			rootDirs = append(rootDirs, top)
		}
		base := path.Base(rel)
		if strings.HasSuffix(strings.ToLower(base), ".exe") {
			hasExe = true
		}
	}

	// 单一顶层目录：正常更新包应把可执行文件等全部放在同一个顶层目录下，
	// 多个顶层目录提示打包错误或攻击者拼凑内容。
	uniqRoots := uniqueStrings(rootDirs)
	if len(uniqRoots) > 1 {
		v.OK = false
		v.Findings = append(v.Findings, UpdateFindings{"error", "zip-multi-root",
			fmt.Sprintf("更新包存在多个顶层目录: %s", strings.Join(uniqRoots, ", "))})
	} else if len(uniqRoots) == 1 {
		v.HasSingleRoot = true
	}
	v.HasLauncherExe = hasExe
	if !hasExe && rootEntries == 0 {
		v.OK = false
		v.Findings = append(v.Findings, UpdateFindings{"error", "zip-no-launcher",
			"更新包内未找到可执行入口"})
	}
	return v
}

// 常量表：文件模式位（对齐 io/fs 定义）。zip 条目来自外部属性，符号链接与
// 设备位按 fs.ModeSymlink / fs.ModeDevice 语义判定，命中任一即拒绝。
const (
	osModeSymlink = 1 << 27 // fs.ModeSymlink
	osModeDevice  = 1 << 26 // fs.ModeDevice
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
