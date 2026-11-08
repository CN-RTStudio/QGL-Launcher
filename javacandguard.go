package main

// javacandguard.go —— “候选 JRE”路径信任判定内核（纯函数）。
//
// 启动器为了让用户少配环境，会在磁盘上枚举可能的 java.exe：Program Files、
// 用户 .minecraft/runtime、常见安装目录等。这个枚举面是真攻击面——
// 一个被塞进扫描目录的恶意 java.exe（带同样文件名）会被启动器当成合法运行时
// 直接 exec。这里把“这个候选路径能不能进入运行时列表”收敛成一组纯判定：
//
//  1) 路径必须落在信任根之内（Program Files / 用户目录下的 runtime），
//     不接受 CWD、临时目录、下载目录、可移动盘根；
//  2) 文件名必须是 java.exe（Windows）或 java（类 Unix），拒绝 javaw 之外的冒名；
//  3) 拒绝路径里的 ..、符号链接穿透、未解析环境变量残留；
//  4) 仅做策略判定，不做 exec、不递归扫描——扫描交给上层。

import (
	"path/filepath"
	"runtime"
	"strings"
)

// JavaCandidate 是一个待裁决的候选 JRE 路径（已规范化为绝对路径）。
type JavaCandidate struct {
	Path string
	// IsSymlink 由上层 stat 得出；本模块只消费结果，不自己 Lstat。
	IsSymlink bool
}

// javaTrustRoots 返回当前平台上允许枚举 JRE 的信任根（绝对、尾部斜杠统一）。
// 不包含用户主目录下的任意位置——用户自己解压到 ~/jre 由配置显式添加，
// 不进自动枚举。
func javaTrustRoots() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Program Files\Java`,
			`C:\Program Files\Eclipse Adoptium`,
			`C:\Program Files\Microsoft\jdk`,
			`C:\Program Files\Zulu`,
			`C:\Program Files\Amazon Corretto`,
			`C:\Program Files (x86)\Java`,
		}
	}
	return []string{"/usr/lib/jvm", "/opt/java", "/usr/opt/jdk"}
}

// normalizeJavaPath 做最小归一：统一分隔符、去掉 ../.. 段、去尾部分隔符。
func normalizeJavaPath(p string) string {
	clean := filepath.Clean(p)
	clean = strings.ReplaceAll(clean, "\\", "/")
	return strings.TrimSuffix(clean, "/")
}

// hasParentTraversal 报告归一前的原始路径里是否显式出现 .. 段。
func hasParentTraversal(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	for _, seg := range strings.Split(p, "\\") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// ValidJavaExecutableName 报告文件名是否为合法 java 可执行名。
func ValidJavaExecutableName(name string) bool {
	base := filepath.Base(name)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(base, "java.exe")
	}
	return base == "java"
}

// ClassifyJavaCandidate 裁决一个候选 JRE。
// 返回 (trustLevel, reasons)：trustLevel 0=拒绝,1=需人工确认,2=信任。
// reasons 非空时描述拒绝/降级原因，便于日志和 UI 提示。
func ClassifyJavaCandidate(c JavaCandidate) (int, []string) {
	var reasons []string
	if c.Path == "" {
		return 0, []string{"empty path"}
	}
	if hasParentTraversal(c.Path) {
		return 0, []string{"path traversal segment .."}
	}
	if strings.ContainsAny(c.Path, "\"'") {
		return 0, []string{"quoting characters in path"}
	}
	if c.IsSymlink {
		// 符号链接本身不是立即拒绝，但降级为需人工确认，防止指向
		// 信任根之外的目标被顺着链带进运行时列表。
		reasons = append(reasons, "symlinked binary")
	}
	norm := normalizeJavaPath(c.Path)
	if !filepath.IsAbs(c.Path) {
		return 0, []string{"relative path not trusted"}
	}
	if !ValidJavaExecutableName(norm) {
		reasons = append(reasons, "executable name is not java/java.exe")
		return 0, reasons
	}
	inRoot := false
	for _, root := range javaTrustRoots() {
		rn := normalizeJavaPath(root)
		if norm == rn || strings.HasPrefix(norm, rn+"/") {
			inRoot = true
			break
		}
	}
	if !inRoot {
		reasons = append(reasons, "outside trust roots: "+norm)
		return 1, reasons
	}
	if len(reasons) > 0 {
		return 1, reasons
	}
	return 2, nil
}

// IsTrustedJavaCandidate 便捷布尔入口：仅当裁决为 2（信任）才返回 true。
func IsTrustedJavaCandidate(c JavaCandidate) bool {
	level, _ := ClassifyJavaCandidate(c)
	return level == 2
}
