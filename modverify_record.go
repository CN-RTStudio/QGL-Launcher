package main

import (
	"strings"
)

func (s *modExpectationStore) record(fileURL string, f ModFile) {
	if fileURL == "" {
		return
	}
	hashes := make(map[string]string, len(f.Hashes)+1)
	for k, v := range f.Hashes {
		if v != "" {
			hashes[strings.ToLower(k)] = strings.ToLower(v)
		}
	}
	// 老版本 API 可能只给顶层 sha1 字段，没有 hashes 表。
	if f.SHA1 != "" {
		if _, ok := hashes["sha1"]; !ok {
			hashes["sha1"] = strings.ToLower(f.SHA1)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(hashes) > 0 {
		s.hashes[fileURL] = hashes
	}
	if f.Size > 0 {
		s.sizes[fileURL] = f.Size
	}
}

// verifyModDownloaded 用登记的期望值校验刚下载完的临时文件。
// 优先全长 sha512，缺失再退 sha1（Modrinth 协议允许只给其一）；
// 同时核对文件大小是否和声明一致。都没有登记则跳过（兼容老版本 API）。
