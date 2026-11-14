package main

import (
	"fmt"
	"os"
)

func openSecurePartFile(partPath string) (*os.File, error) {
	if isSymlink(partPath) {
		return nil, fmt.Errorf("临时文件路径是符号链接，拒绝写入: %s", partPath)
	}
	return os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
}

// finalizeDownloadFile 在完整性校验通过后把临时文件原子改名为最终文件。
// 最终路径若已被调包成符号链接同样拒绝落盘。
func finalizeDownloadFile(partPath, destPath string) error {
	if isSymlink(destPath) {
		os.Remove(partPath)
		return fmt.Errorf("目标路径是符号链接，拒绝落盘: %s", destPath)
	}
	if err := os.Rename(partPath, destPath); err != nil {
		os.Remove(partPath)
		return fmt.Errorf("重命名临时文件失败: %v", err)
	}
	return nil
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
