package main

import (
	"os"
)

func hasASCIIWhitespaceOrControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// MaxFileSize 返回文件大小是否在安全上限内。
// limitBytes <= 0 时用默认 2 GiB。
func MaxFileSize(p string, limitBytes int64) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	if limitBytes <= 0 {
		limitBytes = maxDownloadBytes
	}
	return info.Size() >= 0 && info.Size() <= limitBytes
}

// PathWithin 返回 clean 后的路径，并校验它没有跳出 root。
// 返回 ("", false) 表示路径穿越 / 不存在 / 是符号链接指向外面。
//
// 用法：
//
//	rel, ok := PathWithin("/opt/mc/versions", userSuppliedPath)
//
// 调用方拿到 rel 后再 Join(root, rel) 拼最终绝对路径，绝不直接用 userSuppliedPath。
//
// 安全说明：光做 filepath.Rel 的词法判定挡不住符号链接 / junction——
// root 内若被预先放进一个指向外部目录的链接，词法上路径仍“在 root 里”，
// 实际读写却落到 root 外。这里在词法检查之外再做一次真实路径解析（见
// resolvedInside），任何一段把目标带到 root 之外的链接都判为越界。
