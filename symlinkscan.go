package main

// symlinkscan.go —— 游戏目录符号链接陷阱扫描内核。
//
// 动机：恶意 mod / 残留文件或攻击者写入的符号链接 / junction 会把关键
// 子目录（mods、versions、natives）链到启动器可写目录之外。后续解压或
// 写文件时若跟随该链接，就可能覆盖外部任意路径（Zip Slip 已防解压路径
// 穿越，但“落盘后的链接被后续写入跟随”是另一条路径）。启动预检前扫一遍
// 目录树，命中即告警/拒绝，同时提供前端可查询的报告。

import (
	"os"
	"path/filepath"
	"strings"
)

// maxSymlinkScanDepth 扫描最大递归深度（防止恶意深链拖垮扫描）。
const maxSymlinkScanDepth = 16

// maxSymlinkScanEntries 扫描最大条目数（目录树失控保护）。
const maxSymlinkScanEntries = 20000

// maxSymlinkTrapReports 摘要里最多列出的陷阱条数。
const maxSymlinkTrapReports = 20

// symlinkTrap 是扫描发现的一个符号链接陷阱。
type symlinkTrap struct {
	Path   string `json:"path"`   // 相对游戏根目录的路径
	Target string `json:"target"` // 链接目标（读取失败时为空）
}

// platformSymlinkCheck 判断 path 是否为符号链接类对象（链接 / junction /
// reparse point）。Windows 与 Unix 实现不同，见 *_windows.go / *_unix.go。

// scanSymlinkTraps 遍历 root 下整棵目录树，返回所有符号链接陷阱（相对路径）。
// 深度 / 条目超限时提前停止（部分结果仍返回，err 说明截断原因）。
func scanSymlinkTraps(root string) ([]symlinkTrap, error) {
	var traps []symlinkTrap
	entries := 0
	var walkErr error
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// 单条目读取失败不中断整棵扫描，继续（防一个坏条目挡住全部）。
			return nil
		}
		if path == root {
			return nil
		}
		entries++
		if entries > maxSymlinkScanEntries {
			walkErr = errSymlinkScanLimit
			return filepath.SkipAll
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// 目录深度控制：超过上限的子树不再进入。
			if depth := strings.Count(rel, "/"); depth >= maxSymlinkScanDepth {
				return filepath.SkipDir
			}
		}
		if !platformSymlinkCheck(path) {
			return nil
		}
		target := ""
		if t, err := os.Readlink(path); err == nil {
			target = t
		}
		traps = append(traps, symlinkTrap{Path: rel, Target: target})
		return nil
	})
	if err != nil && walkErr == nil {
		walkErr = err
	}
	return traps, walkErr
}

// errSymlinkScanLimit 是扫描条目超限的截断标记。
var errSymlinkScanLimit = errSymlinkScanLimitType("symlink-scan-limit")

type errSymlinkScanLimitType string

func (e errSymlinkScanLimitType) Error() string { return string(e) }

// symlinkTrapSummary 把陷阱列表整理成可读摘要（供启动预检报错/前端展示）。
// limit<=0 时取 maxSymlinkTrapReports。
func symlinkTrapSummary(traps []symlinkTrap, limit int) []string {
	if limit <= 0 || limit > maxSymlinkTrapReports {
		limit = maxSymlinkTrapReports
	}
	if len(traps) == 0 {
		return nil
	}
	if len(traps) > limit {
		traps = traps[:limit]
	}
	out := make([]string, 0, len(traps))
	for _, t := range traps {
		if t.Target != "" {
			out = append(out, t.Path+" -> "+t.Target)
		} else {
			out = append(out, t.Path)
		}
	}
	return out
}
