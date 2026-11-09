package main

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
