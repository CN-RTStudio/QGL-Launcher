package main

import (
	"sync"
)

// ===== 期望值存储（并发安全） =====

// modExpectationStore 保存“某个下载 URL 应该长什么样”的元数据：
// Modrinth 声明的哈希集合与文件大小。key 一律是下载 URL。
type modExpectationStore struct {
	mu     sync.RWMutex
	hashes map[string]map[string]string // fileURL -> 算法名(小写) -> 十六进制摘要(小写)
	sizes  map[string]int64             // fileURL -> Modrinth 声明的字节数
}

func newModExpectationStore() *modExpectationStore {
	return &modExpectationStore{
		hashes: map[string]map[string]string{},
		sizes:  map[string]int64{},
	}
}

// record 登记一个文件的期望哈希和大小。f 来自 Modrinth 版本元数据。
