package main

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
