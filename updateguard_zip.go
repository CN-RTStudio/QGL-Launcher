package main

import (
	"archive/zip"
	"fmt"
	"path"
	"sort"
	"strings"
)

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
func SummarizeUpdateVerdict(v UpdateVerdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OK=%v entries=%d bytes=%d singleRoot=%v launcherExe=%v",
		v.OK, v.ZipEntryCount, v.ZipTotalBytes, v.HasSingleRoot, v.HasLauncherExe)
	for _, f := range v.Findings {
		fmt.Fprintf(&b, " [%s:%s %s]", f.Severity, f.Code, f.Message)
	}
	return b.String()
}
