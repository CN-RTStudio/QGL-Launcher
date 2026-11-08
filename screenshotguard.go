package main

// screenshotguard.go —— 截图与媒体文件的文件名/目录安全校验内核。
//
// 背景：
//   启动器支持对游戏窗口截图并保存到用户目录。文件名若直接拼接用户输入（例如
//   自定义文件名模板里的服务器名/世界名），就会出现三类真实问题：
//     1) 路径注入：名字带 ".."、"/"、绝对路径前缀 -> 文件写到任意目录（覆盖或
//        越界写）；
//     2) 控制字符/非法字符：Windows 下 \x00、< > : " | ? * 会让保存失败或行为
//        怪异，控制字符还可能被日志/终端解释；
//     3) Windows 保留设备名：CON/PRN/AUX/NUL/COM1-9/LPT1-9 会被系统当作设备，
//        写文件不是报错就是写到设备流上；
//     4) 目录被符号链接替换 -> 保存跟随链接落到实例根之外。
//   本模块对"名字 -> 磁盘路径"这一段做收口：名字只允许作为单一段落文件名，
//   目录必须真实存在于允许根内且不含逃逸链接。

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ScreenshotLimits 限定截图文件名与目录的边界。
type ScreenshotLimits struct {
	MaxNameRunes  int
	MaxDirRunes   int
	MaxTotalRunes int
	AllowSubdirs  bool // 是否允许文件名带子目录（默认不允许，只允许单段）
}

func (l *ScreenshotLimits) withDefaults() ScreenshotLimits {
	if l == nil {
		l = &ScreenshotLimits{}
	}
	out := *l
	if out.MaxNameRunes <= 0 {
		out.MaxNameRunes = 120
	}
	if out.MaxDirRunes <= 0 {
		out.MaxDirRunes = 4096
	}
	if out.MaxTotalRunes <= 0 {
		out.MaxTotalRunes = 8192
	}
	return out
}

// winReservedNames 是 Windows 保留设备名（大小写不敏感，含扩展名前缀也保留）。
var winReservedNames = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

// winForbiddenChars 是 Windows 文件名禁止的字符。
var winForbiddenChars = []rune{'<', '>', ':', '"', '|', '?', '*'}

// isWinReservedName 判断文件名主干（去扩展名后）是否是保留设备名。
func isWinReservedName(name string) bool {
	base := name
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	upper := strings.ToUpper(base)
	for _, r := range winReservedNames {
		if upper == r {
			return true
		}
	}
	// CON 加尾巴（CON.txt、CONIN、CONOUT）也保留
	if strings.HasPrefix(upper, "CON") && len(upper) > 3 {
		rest := upper[3:]
		// 只有紧跟点或数字的才保留（CON.abc / CON5）；普通 CONfig 不保留
		if rest[0] == '.' || (rest[0] >= '1' && rest[0] <= '9') {
			return true
		}
	}
	return false
}

// SanitizeScreenshotName 校验并净化单个截图文件名；返回净化后的名字。
func SanitizeScreenshotName(name string, lim ScreenshotLimits) (string, error) {
	d := lim.withDefaults()
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errors.New("screenshot name is empty")
	}
	if len([]rune(trimmed)) > d.MaxNameRunes {
		return "", errors.New("screenshot name too long")
	}
	if hasControlCharStr(trimmed) {
		return "", errors.New("screenshot name contains control characters")
	}
	if !d.AllowSubdirs {
		if strings.ContainsAny(trimmed, `/\`) {
			return "", errors.New("screenshot name must be a single path segment")
		}
		if strings.Contains(trimmed, "..") {
			return "", errors.New("screenshot name must not contain ..")
		}
	} else {
		// 允许带子目录（sub/dir/file.png），但逐段拒绝父目录穿越与绝对路径：
		// 旧实现直接跳过整段检查，"../../escape" 会被 filepath.Join 拼出根外。
		if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, `\`) {
			return "", errors.New("screenshot name must not be absolute")
		}
		norm := strings.ReplaceAll(trimmed, `\`, "/")
		for _, seg := range strings.Split(norm, "/") {
			if seg == "" {
				return "", errors.New("screenshot name has empty path segment")
			}
			if seg == "." || seg == ".." {
				return "", errors.New("screenshot name must not contain dot segments")
			}
		}
	}
	for _, c := range winForbiddenChars {
		if strings.ContainsRune(trimmed, c) {
			return "", errors.New("screenshot name contains forbidden character")
		}
	}
	// 设备名只按最终文件名主干判定（带子目录时不能拿整段路径去比）。
	nameBase := trimmed
	if i := strings.LastIndexAny(nameBase, `/\`); i >= 0 {
		nameBase = nameBase[i+1:]
	}
	if isWinReservedName(nameBase) {
		return "", errors.New("screenshot name is a reserved device name")
	}
	if nameBase == "." || nameBase == ".." {
		return "", errors.New("screenshot name must not be dot path")
	}
	return trimmed, nil
}

// ValidateScreenshotDir 校验截图目录：绝对路径、限长、真实存在，且不是符号链接
// 逃逸（解析后仍须在允许根内）。
func ValidateScreenshotDir(dir, allowRoot string, lim ScreenshotLimits) (string, error) {
	d := lim.withDefaults()
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("screenshot dir is empty")
	}
	if len([]rune(dir)) > d.MaxDirRunes {
		return "", errors.New("screenshot dir too long")
	}
	if hasControlCharStr(dir) {
		return "", errors.New("screenshot dir contains control characters")
	}
	if strings.HasPrefix(dir, `\\`) || strings.HasPrefix(dir, `//`) {
		return "", errors.New("screenshot dir must not be a UNC path")
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("screenshot dir must be absolute")
	}
	clean := filepath.Clean(dir)
	if clean != dir {
		return "", errors.New("screenshot dir must be normalized")
	}
	info, err := os.Stat(clean)
	if err != nil {
		return "", errors.New("screenshot dir not accessible")
	}
	if !info.IsDir() {
		return "", errors.New("screenshot path is not a directory")
	}
	if allowRoot != "" {
		resolvedDir, err1 := filepath.EvalSymlinks(clean)
		resolvedRoot, err2 := filepath.EvalSymlinks(allowRoot)
		if err1 == nil && err2 == nil {
			rel, err3 := filepath.Rel(resolvedRoot, resolvedDir)
			if err3 != nil {
				return "", errors.New("cannot resolve screenshot dir relative to root")
			}
			if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return "", errors.New("screenshot dir escapes allowed root")
			}
		}
	}
	return clean, nil
}

// BuildScreenshotPath 组合校验：目录 + 名字 -> 完整路径；总长再限一次。
func BuildScreenshotPath(dir, name string, allowRoot string, lim ScreenshotLimits) (string, error) {
	d := lim.withDefaults()
	cleanDir, err := ValidateScreenshotDir(dir, allowRoot, d)
	if err != nil {
		return "", err
	}
	cleanName, err := SanitizeScreenshotName(name, d)
	if err != nil {
		return "", err
	}
	full := filepath.Join(cleanDir, cleanName)
	if len([]rune(full)) > d.MaxTotalRunes {
		return "", errors.New("full screenshot path too long")
	}
	return full, nil
}

// SummarizeScreenshotError 把截图路径错误压成一行可读文本。
func SummarizeScreenshotError(err error) string {
	if err == nil {
		return "screenshot path ok"
	}
	return "screenshot path rejected: " + err.Error()
}
