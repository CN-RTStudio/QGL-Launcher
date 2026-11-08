package main

// modverify.go 收口 Mod 下载链路上三件以前散落在 mod.go 里、且各有真实缺口的东西：
//
//  1. 期望值存储（哈希/大小）。旧实现是两个裸包级 map，登记动作发生在
//     downloadMutex 加锁之前，前端并发点两个“下载 Mod”就会触发 Go 运行时
//     fatal "concurrent map writes" 直接崩掉整个启动器；下载 goroutine 同时
//     还在无锁读这两个 map。这里用独立 RWMutex 收口全部读写。
//  2. 下载主机白名单。旧实现只校验 https://，被攻陷/伪造的 Modrinth 版本
//     元数据可以把文件 URL 指到任意外部主机，没有哈希的文件会被原样下载
//     进 mods 目录并随游戏执行。重定向跳转同样可能把官方主机甩到任意主机。
//  3. 符号链接安全落盘。O_CREATE 在目标已是符号链接时会顺着链接写穿到
//     链接指向的任意文件（mods 目录可被本地其它程序预置 .part 链接）。
//
// 外部协议要求的摘要算法（Modrinth 的 sha512/sha1）按协议保留，不替换。

import (
	"strings"
	"sync"
)

// ===== 期望值存储（并发安全） =====

// modExpectationStore 保存“某个下载 URL 应该长什么样”的元数据：
// Modrinth 声明的哈希集合与文件大小。key 一律是下载 URL。
type modExpectationStore struct {
	mu     sync.RWMutex
	hashes map[string]map[string]string // fileURL -> 算法名(小写) -> 十六进制摘要(小写)
	sizes  map[string]int64            // fileURL -> Modrinth 声明的字节数
}

func newModExpectationStore() *modExpectationStore {
	return &modExpectationStore{
		hashes: map[string]map[string]string{},
		sizes:  map[string]int64{},
	}
}

// record 登记一个文件的期望哈希和大小。f 来自 Modrinth 版本元数据。
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

// lookup 返回某 URL 的期望哈希（副本，调用方随便改）和期望大小。
// registered 表示该 URL 是否登记过任一期望值，行为对齐旧实现
// “没有期望值就不做完整性校验、不阻塞下载”的约定。
func (s *modExpectationStore) lookup(fileURL string) (hashes map[string]string, wantSize int64, registered bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	wantSize, hasSize := s.sizes[fileURL]
	src, hasHashes := s.hashes[fileURL]
	if hasHashes {
		hashes = make(map[string]string, len(src))
		for k, v := range src {
			hashes[k] = v
		}
	}
	registered = hasHashes || (hasSize && wantSize > 0)
	return hashes, wantSize, registered
}

// delete 清掉某 URL 的期望值。下载流程结束（成功落盘 / 校验失败 / 跳过）
// 后都应调用，避免 map 随下载历史无限增长。
func (s *modExpectationStore) delete(fileURL string) {
	s.mu.Lock()
	delete(s.hashes, fileURL)
	delete(s.sizes, fileURL)
	s.mu.Unlock()
}

// modExpect 是包级唯一实例。
var modExpect = newModExpectationStore()
