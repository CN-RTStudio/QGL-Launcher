package main

import (
	"time"
)

func isReclaimableMetaName(name string) (base string, ok bool) {
	if len(name) <= len(reclaimedMetaSuffix) {
		return "", false
	}
	if name[len(name)-len(reclaimedMetaSuffix):] != reclaimedMetaSuffix {
		return "", false
	}
	base = name[:len(name)-len(reclaimedMetaSuffix)]
	if base == "" || base == "." {
		return "", false
	}
	return base, true
}
func isNativeTempName(name string) bool {
	return isReclaimableTempName(name) && name[:len(reclaimedNativePrefix)] == reclaimedNativePrefix
}

type reclaimCandidateInput struct {
	Name       string
	WithinRoot bool // 已解析符号链接后是否仍严格位于根目录内
	IsSymlink  bool // 该条目或其任一祖先是否为符号链接
	IsRegular  bool // 是否普通文件
	Mtime      time.Time
	Size       int64
	BaseExists bool // 仅对 .qglmeta：同目录基础文件是否存在
	Now        time.Time
}
