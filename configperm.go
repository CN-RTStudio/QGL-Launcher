package main

// configperm.go —— 敏感文件权限审计内核。
//
// 背景：safeio 管“新写入”的安全（原子写、0600、不随符号链接），configguard 管
// “内容”的白名单，但历史遗留或用户手动改过权限的既有敏感文件（accounts/*.json、
// password.json、config.json、会话日志）没有任何审计：如果被同机其他账户改成
// 0644/0777，或被人替换成指向别处的符号链接，启动器下次启动时照样读取，密码、
// 微软登录令牌、配置就可能落到别的账户手里。
//
// 本模块在启动时枚举这些敏感路径并逐个审计：
//  1. 符号链接 / 非常规文件（可能指向受害者文件或设备文件，拒绝跟随）；
//  2. Unix 下 mode 的 group/other 位非零（同机其他账户可读，应收敛 0600）；
//  3. Windows 下 HIDDEN / SYSTEM 属性（文件被有意掩盖或替换后不易被发现）。
//
// 结果分 ok / warn（可自动收敛）/ block（需人工处理）三级，由接线方决定是
// 用 os.Chmod 收敛还是写安全审计事件。

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	permSeverityOK    = "ok"
	permSeverityWarn  = "warn"
	permSeverityBlock = "block"

	permMaxAuditDepth = 4          // 敏感路径递归深度上限，防误扫整盘
	permMaxMetaBytes  = 8 << 20    // 8 MiB，超限文件只看元数据不读内容
)

// PermFinding 是单条权限审计结论（对 Wails 前端直接可用）。
type PermFinding struct {
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Issue    string `json:"issue"`
	Mode     string `json:"mode"`
	Size     int64  `json:"size"`
	Suggest  string `json:"suggest"`
}

// permSensitiveGroups 描述数据目录下哪些子目录 / 文件属于敏感面。
type permSensitiveGroup struct {
	dir      string // 相对数据目录的子目录；"." 表示根
	patterns []string
}

var permSensitiveGroups = []permSensitiveGroup{
	{dir: "accounts", patterns: []string{"*.json"}},
	{dir: "logs", patterns: []string{"*.log", "*.jsonl"}},
	{dir: ".", patterns: []string{"password.json", "config.json", "ms_auth.json", "external_auth.json", "salt.bin", "launchsnapshot.json"}},
}

// AuditSensitivePermissions 在 root 下枚举敏感文件并审计，按路径排序返回。
// root 为空或不存在时返回 nil（启动路径缺失不是安全事件，交给调用方决定）。
func AuditSensitivePermissions(root string) []PermFinding {
	if root == "" {
		return nil
	}
	var out []PermFinding
	for _, grp := range permSensitiveGroups {
		base := filepath.Join(root, grp.dir)
		for _, pat := range grp.patterns {
			out = append(out, auditPattern(base, pat)...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func auditPattern(dir, pattern string) []PermFinding {
	if strings.ContainsAny(pattern, "*?[") {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil
		}
		out := make([]PermFinding, 0, len(matches))
		for _, m := range matches {
			if f := auditOne(m); f.Severity != permSeverityOK || f.Issue != "" {
				out = append(out, f)
			}
		}
		return out
	}
	full := filepath.Join(dir, pattern)
	if st, err := os.Lstat(full); err == nil && !st.IsDir() {
		if f := auditOne(full); f.Severity != permSeverityOK || f.Issue != "" {
			return []PermFinding{f}
		}
	}
	return nil
}

func auditOne(path string) PermFinding {
	li, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return PermFinding{Path: path, Severity: permSeverityOK}
		}
		return PermFinding{Path: path, Severity: permSeverityBlock, Issue: "lstat-failed", Suggest: "文件无法读取元数据，检查是否被其他进程占用或删除"}
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return PermFinding{Path: path, Severity: permSeverityBlock, Issue: "symlink", Suggest: "符号链接指向其他位置，拒绝读取；删除并让启动器重建"}
	}
	if !li.Mode().IsRegular() {
		return PermFinding{Path: path, Severity: permSeverityBlock, Issue: "non-regular", Suggest: "非常规文件（设备/管道/目录），拒绝读取"}
	}
	f := PermFinding{Path: path, Severity: permSeverityOK, Mode: li.Mode().String(), Size: li.Size()}
	if f.Size > permMaxMetaBytes {
		f.Issue = "oversize"
		f.Suggest = "敏感文件超过 8 MiB，疑似被篡改或写入垃圾数据"
		return f
	}
	if runtime.GOOS == "windows" {
		utf16Path, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return f
		}
		attrs, err := windows.GetFileAttributes(utf16Path)
		if err != nil {
			return f
		}
		var issues []string
		if attrs&windows.FILE_ATTRIBUTE_HIDDEN != 0 {
			issues = append(issues, "hidden")
		}
		if attrs&windows.FILE_ATTRIBUTE_SYSTEM != 0 {
			issues = append(issues, "system")
		}
		if len(issues) > 0 {
			f.Severity = permSeverityWarn
			f.Issue = strings.Join(issues, ",")
			f.Suggest = "隐藏/系统属性说明文件被有意掩盖，确认后清除属性并保持 0600"
		}
		return f
	}
	perm := li.Mode().Perm()
	if perm&0o077 != 0 {
		f.Severity = permSeverityWarn
		f.Issue = "world-readable"
		f.Suggest = "同机其他账户可读，应收敛为 0600"
		return f
	}
	if perm&0o700 != 0o600 && perm&0o700 != 0o700 {
		f.Severity = permSeverityWarn
		f.Issue = "unexpected-mode"
		f.Suggest = "权限位不是预期的 0600/0700，确认后收敛"
	}
	return f
}

// BlockedFindings 只返回需要人工处理的 block 级结论（符号链接等）。
func BlockedFindings(findings []PermFinding) []PermFinding {
	var out []PermFinding
	for _, f := range findings {
		if f.Severity == permSeverityBlock {
			out = append(out, f)
		}
	}
	return out
}

// WarnFindings 只返回可自动收敛的 warn 级结论。
func WarnFindings(findings []PermFinding) []PermFinding {
	var out []PermFinding
	for _, f := range findings {
		if f.Severity == permSeverityWarn {
			out = append(out, f)
		}
	}
	return out
}

// ConvergePermissions 把 warn 级发现收敛为 0600：Lstat 复核常规文件后 Chmod。
// 只改权限位不重写内容，符号链接 / 非常规文件一概不碰；返回收敛成功与失败清单。
func ConvergePermissions(findings []PermFinding) (fixed []string, failed []string) {
	for _, f := range findings {
		if f.Severity != permSeverityWarn {
			continue
		}
		li, err := os.Lstat(f.Path)
		if err != nil || !li.Mode().IsRegular() || li.Mode()&os.ModeSymlink != 0 {
			failed = append(failed, f.Path)
			continue
		}
		if err := os.Chmod(f.Path, 0o600); err != nil {
			failed = append(failed, f.Path)
			continue
		}
		fixed = append(fixed, f.Path)
	}
	return fixed, failed
}
